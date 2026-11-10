"""D2-A first integrated candidate. Private synthetic SQL experiment only.

Frozen RC3/REF4 sources are imported unmodified. Exact SQL intent binding is a
new adapter obligation. The trusted callback writes inside the real consumer
transaction. StagedRoot, baseline and full D2-A qualification are not included.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "fci-cou40-ref4-20261020"))
from integrated_service import IntegratedService
from fci_hardened.service import CONTEXT, clock, protected_file
from fci_hardened.spend_ledger import ticket_digest
from authorization import (AuthorizationRefused, OP_FIELDS, bind, canonical,
                           exact_shape, require, strict_loads, verify_signature)

SCHEMA = "FCI-SQL-D2A-FIRST-INTEGRATION/1"
FAULTS = ("none", "I4", "I5")


class SqlService(IntegratedService):
    def __init__(self, runtime, *, journal, fault="none"):
        self.journal = Path(journal)
        self.fault = fault
        self.active = None
        self.effect_attempted = False
        super().__init__(runtime, request_id="D2A_ENTRY", event_hook=self.capture)
        config = strict_loads(protected_file(self.runtime / "d2a-public.json"))
        exact_shape(config, ("public_key",))
        require(type(config["public_key"]) is str, "PUBLIC_KEY")
        self.public_key = bytes.fromhex(config["public_key"])
        require(len(self.public_key) == 32, "PUBLIC_KEY")
        meta = self.meta()
        require(meta["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "BOOT_CHANGED")
        # Existing schema and data only. No CREATE/repair/reset on startup.
        self.consumer.db.execute("SELECT authorization_digest,ticket_digest FROM demo_effects LIMIT 1")
        self.consumer.db.execute("SELECT envelope,phase FROM d2_operations LIMIT 1")
        if self.consumer.db.execute("SELECT 1 FROM d2_operations WHERE phase IN ('STAGED','PREPARED')").fetchone():
            self.consumer.db.execute("UPDATE d2_meta SET recovery=1 WHERE id=1")

    def meta(self):
        rows = self.consumer.db.execute("SELECT epoch,recovery,deployment_id,boot_id FROM d2_meta WHERE id=1").fetchall()
        require(len(rows) == 1, "META_MISSING")
        epoch, recovery, deployment, boot = rows[0]
        require(type(epoch) is int and 0 <= epoch < 2**63-1 and recovery in (0, 1), "META_INVALID")
        return {"epoch": epoch, "recovery": recovery, "deployment_id": deployment, "boot_id": boot}

    def authority_status(self):
        if self.poisoned or self.meta()["recovery"]:
            return "RECOVERY_REQUIRED"
        if self.authority.state().mask or self.consumer._state().mask:
            return "LATCHED"
        return "READY"

    def reply(self, code, *, decision="REFUSED", effect="UNKNOWN", new=False, evidence=None):
        return {"code": code, "decision": decision, "effect_status": effect,
                "authority_status": self.authority_status(), "new_effect": new,
                "evidence_ref": evidence}

    def record(self, kind, **data):
        row = {"schema": SCHEMA, "kind": kind, "uid": os.geteuid(),
               "operation_id": self.active["operation"]["operation_id"] if self.active else None,
               "monotonic_tick": clock(), **data}
        with self.journal.open("a") as out:
            out.write(json.dumps(row, sort_keys=True) + "\n"); out.flush(); os.fsync(out.fileno())

    def validate(self, request, uid, *, history=False):
        m = self.meta()
        return bind(request["authorization"], request["operation"], self.public_key,
                    uid=uid, role=self.roles.get(uid), deployment_id=m["deployment_id"],
                    policy_digest=self.policy.digest, context=CONTEXT, boot_id=m["boot_id"],
                    epoch=m["epoch"], now=clock(), history=history)

    def operation_row(self, rid):
        return self.consumer.db.execute(
            "SELECT envelope,authorization_digest,uid,ticket_digest,phase FROM d2_operations WHERE operation_id=?",
            (rid,)).fetchone()

    def capture(self, kind, data, raw, service):
        if kind == "tx_stage" and data.get("operation") == "rearm" and raw.get("result_code") == "REARM_LOCAL_ACCEPTED":
            # Same real consumer transaction as the accepted local rearm.
            self.resolve_before_rearm()
            service.consumer.db.execute("UPDATE d2_meta SET epoch=epoch+1,recovery=0 WHERE id=1")
        if kind == "tx_stage" and data.get("operation") == "finish" and raw.get("result_new_effect"):
            require(self.active is not None and service.consumer.db.in_transaction, "NO_BOUND_TRANSACTION")
            req, uid = self.active, self.active_uid
            rid = req["operation"]["operation_id"]
            digest = self.validate(req, uid)
            row = self.operation_row(rid)
            require(row is not None and row[0] == canonical(req["authorization"]).decode()
                    and row[1] == digest and row[2] == uid and row[4] == "PREPARED", "DURABLE_BINDING")
            entry = service.consumer._entry(rid)
            td = ticket_digest(entry["ticket"])
            require(row[3] == td and entry["ticket"]["token"]["body"]["request_id"] == rid,
                    "TICKET_BINDING")
            require(self.meta()["recovery"] == 0, "RECOVERY_REQUIRED")
            body = req["authorization"]["body"]
            cursor = service.consumer.db.execute(
                "UPDATE demo_configuration SET value=?,version=version+1 WHERE target=? AND version=?",
                (body["value"], body["target"], body["expected_version"]))
            require(cursor.rowcount == 1, "SQL_PRECONDITION")
            service.consumer.db.execute(
                "INSERT INTO demo_effects(operation_id,target,old_version,new_version,value,authorization_digest,ticket_digest) VALUES(?,?,?,?,?,?,?)",
                (rid, body["target"], body["expected_version"], body["expected_version"]+1, body["value"], digest, td))
            service.consumer.db.execute("UPDATE d2_operations SET phase='COMMITTED' WHERE operation_id=?", (rid,))
            self.record("sql_staged", authorization_digest=digest, ticket_digest=td)
            if self.fault == "I4":
                os._exit(73)
        self.record(kind, operation=data.get("operation"), result_code=raw.get("result_code"))
        if kind == "tx_commit" and data.get("operation") == "finish" and self.fault == "I5":
            os._exit(73)

    def inspect_operation(self, rid):
        row = self.operation_row(rid)
        if row is None:
            require(not self.consumer.db.execute("SELECT 1 FROM demo_effects WHERE operation_id=?", (rid,)).fetchone(), "ORPHAN_EFFECT")
            entry = self.consumer._entry(rid)
            require(entry is None or entry["status"] != "DONE", "ORPHAN_CONSUMER_EFFECT")
            return self.reply("NO_OPERATION", effect="NOT_COMMITTED_PROVEN")
        effects = self.consumer.db.execute(
            "SELECT event_id,authorization_digest,ticket_digest,target,old_version,new_version,value FROM demo_effects WHERE operation_id=?", (rid,)).fetchall()
        if row[4] == "COMMITTED":
            envelope = strict_loads(row[0].encode())
            body = envelope["body"]
            require(verify_signature(envelope, self.public_key) == row[1], "HISTORY_SIGNATURE")
            require(len(effects) == 1 and effects[0][1:] ==
                    (row[1], row[3], body["target"], body["expected_version"],
                     body["expected_version"]+1, body["value"]), "INCONSISTENT_EFFECT")
            entry = self.consumer._entry(rid)
            require(entry is not None and entry["status"] == "DONE"
                    and ticket_digest(entry["ticket"]) == row[3], "INCONSISTENT_CONSUMER_EFFECT")
            return self.reply("ACK_EFFECT_HISTORY", decision="REPLAY", effect="COMMITTED_PROVEN",
                              evidence={"operation_id": rid, "authorization_digest": row[1],
                                        "ticket_digest": row[3], "event_id": effects[0][0]})
        if row[4] == "QUARANTINED" and not effects:
            return self.reply("BLOCK_QUARANTINED", effect="NOT_COMMITTED_PROVEN")
        return self.reply("OUTCOME_UNKNOWN", decision="UNKNOWN", new=None)

    def resolve_before_rearm(self):
        # Trusted single writer at a quiescent entry boundary; never repair a
        # disagreement between a DONE consumer and a missing application effect.
        for rid, in self.consumer.db.execute("SELECT operation_id FROM d2_operations WHERE phase IN ('STAGED','PREPARED')").fetchall():
            require(not self.consumer.db.execute("SELECT 1 FROM demo_effects WHERE operation_id=?", (rid,)).fetchone(), "UNRESOLVED_EFFECT")
            entry = self.consumer._entry(rid)
            require(entry is None or entry.get("status") != "DONE", "UNRESOLVED_CONSUMER")
            self.consumer.db.execute("UPDATE d2_operations SET phase='QUARANTINED' WHERE operation_id=?", (rid,))

    def execute(self, uid, req):
        exact_shape(req, ("op", "operation", "authorization"))
        # Validate authentication and identity before any operation lookup.
        digest = self.validate(req, uid, history=True)
        rid = req["operation"]["operation_id"]
        row = self.operation_row(rid)
        if row is not None:
            require(row[1] == digest and row[0] == canonical(req["authorization"]).decode(), "ID_CONFLICT")
            return self.inspect_operation(rid)
        self.validate(req, uid)
        self.consumer.db.execute(
            "INSERT INTO d2_operations VALUES(?,?,?,?,?,?)",
            (rid, canonical(req["authorization"]).decode(), digest, uid, None, "STAGED"))
        body = req["authorization"]["body"]
        current = self.consumer.db.execute("SELECT version FROM demo_configuration WHERE target=?", (body["target"],)).fetchone()
        if self.authority_status() != "READY" or current != (body["expected_version"],):
            self.consumer.db.execute("UPDATE d2_operations SET phase='QUARANTINED' WHERE operation_id=?", (rid,))
            return self.inspect_operation(rid)
        self.active, self.active_uid, self.request_id = req, uid, rid
        try:
            prepared = IntegratedService.handle(self, uid, canonical({"op":"prepare", "request_id":rid,"action":"COAST"}))
            if prepared.get("code") != "DISPATCH_RECORDED":
                return self.unknown()
            td = ticket_digest(prepared["ticket"])
            self.consumer.db.execute("UPDATE d2_operations SET ticket_digest=? WHERE operation_id=?", (td, rid))
            delivered = IntegratedService.handle(self, uid, canonical({"op":"deliver","ticket":prepared["ticket"]}))
            if delivered.get("code") != "DELIVERED":
                self.consumer.db.execute("UPDATE d2_operations SET phase='QUARANTINED' WHERE operation_id=?", (rid,))
                return self.inspect_operation(rid)
            self.consumer.db.execute("UPDATE d2_operations SET phase='PREPARED' WHERE operation_id=?", (rid,))
            self.effect_attempted = True
            result = IntegratedService.handle(self, uid, canonical({"op":"finish","request_id":rid}))
            if result == {"code":"EFFECT_COMMITTED", "new_effect":True}:
                answer = self.inspect_operation(rid)
                answer.update(code="SQL_EFFECT_COMMITTED",decision="ACCEPTED",new_effect=True)
                return answer
            # Ambiguous core errors are never rewritten as proof of no effect.
            if result.get("code", "").startswith("OUTCOME_UNKNOWN"):
                return self.unknown()
            if self.operation_row(rid)[4] == "COMMITTED":
                return self.unknown()
            self.consumer.db.execute("UPDATE d2_operations SET phase='QUARANTINED' WHERE operation_id=?", (rid,))
            return self.inspect_operation(rid)
        finally:
            self.active = None

    def unknown(self):
        self.poisoned = True
        self.consumer.db.execute("UPDATE d2_meta SET recovery=1 WHERE id=1")
        return self.reply("OUTCOME_UNKNOWN",decision="UNKNOWN",new=None)

    def handle(self, uid, raw):
        if threading.get_ident() != self._owner_thread or uid not in self.roles:
            return self.reply("BLOCK_ROLE")
        with self._entry_lock:
            self.effect_attempted = False
            try:
                req = strict_loads(raw)
                require(type(req) is dict and type(req.get("op")) is str, "INPUT")
                op, role = req["op"], self.roles[uid]
                if op == "execute":
                    require(role == "requester", "ROLE")
                    return self.execute(uid, req)
                if op == "inspect":
                    exact_shape(req, ("op", "operation_id"))
                    require(type(req["operation_id"]) is str, "RID")
                    return self.inspect_operation(req["operation_id"])
                if op == "status":
                    exact_shape(req, ("op",))
                    return {"code":"STATUS", "candidate":SCHEMA, "authority_status":self.authority_status(),
                            "epoch":self.meta()["epoch"], "policy":self.policy.digest}
                if role == "maintainer" and op == "fixture_conditions":
                    exact_shape(req, ("op", "healthy")); require(type(req["healthy"]) is bool, "INPUT")
                    self.conditions = (req["healthy"], True, True, True, True)
                    return {"code":"FIXTURE_CONDITIONS_SET"}
                if role == "maintainer" and op in ("rearm_state", "rearm_authority", "rearm_local"):
                    return IntegratedService.handle(self, uid, raw)
                return self.reply("BLOCK_ROLE")
            except AuthorizationRefused as error:
                if self.effect_attempted:
                    return self.unknown()
                return self.reply("BLOCK_" + str(error))
            except Exception:
                try:
                    return self.unknown()
                except Exception:
                    self.poisoned = True
                    return {"code":"OUTCOME_UNKNOWN", "decision":"UNKNOWN", "effect_status":"UNKNOWN",
                            "authority_status":"RECOVERY_REQUIRED", "new_effect":None, "evidence_ref":None}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("runtime", type=Path)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--fault", choices=FAULTS, default="none")
    a = parser.parse_args()
    SqlService(a.runtime, journal=a.journal, fault=a.fault).serve()
