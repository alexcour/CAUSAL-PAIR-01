"""D0 SQL integration of the frozen REF4 service; private experiment only.

The target is one fixed synthetic configuration in the consumer transaction.
This does not turn the research fixture into a generic SQL gateway.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "fci-cou40-ref4-20261020"))
from integrated_service import IntegratedService
from fci_hardened.service import protected_file
from fci_hardened.strict_json import canonical, loads, shape

SCHEMA = "FCI-SQL-DEMO-D0/1"
OPERATION = {"operation_id": "CFG001", "target": "synthetic-config",
             "expected_version": 0, "value": 1}


class SqlDemoService(IntegratedService):
    def __init__(self, runtime, *, journal, fault="none"):
        self.journal = Path(journal)
        self.fault = fault
        self.operation = json.loads(protected_file(Path(runtime) / "demo-operation.json"))
        if self.operation != OPERATION:
            raise ValueError("D0 supports only the deployed fixed operation")
        super().__init__(runtime, request_id=OPERATION["operation_id"], event_hook=self.capture)
        # No table creation or reset at service startup. Provisioning is offline.
        self.consumer.db.execute("SELECT version,value FROM demo_configuration WHERE target=?",
                                 (OPERATION["target"],)).fetchone()

    def record(self, row):
        with self.journal.open("a", encoding="utf-8") as out:
            out.write(json.dumps({"schema": SCHEMA, "uid": os.geteuid(),
                                  "monotonic_ns": time.monotonic_ns(), **row}, sort_keys=True) + "\n")
            out.flush()
            os.fsync(out.fileno())

    def capture(self, kind, data, raw, service):
        # Retain selected non-secret instrumentation only. Never log keys,
        # tickets, witness bodies, signatures or raw inherited callback data.
        row = {"kind": kind, "operation": data.get("operation"),
               "result_code": raw.get("result_code"),
               "result_new_effect": raw.get("result_new_effect")}
        if kind == "tx_stage" and data.get("operation") == "finish" and raw.get("result_new_effect"):
            db = service.consumer.db
            if not db.in_transaction:
                raise RuntimeError("SQL target write outside original consumer transaction")
            entry = service.consumer._entry(self.request_id)
            if entry["ticket"]["token"]["body"]["action"] != {"op": "set_level", "value": 1}:
                raise RuntimeError("fixed operation/action mismatch")
            updated = db.execute(
                "UPDATE demo_configuration SET value=?,version=version+1 WHERE target=? AND version=?",
                (OPERATION["value"], OPERATION["target"], OPERATION["expected_version"]))
            if updated.rowcount != 1:
                raise RuntimeError("configuration precondition conflict")
            # The event ID is unique; operation_id deliberately is NOT unique.
            # A duplicate callback must be observable, not hidden by the log.
            db.execute("INSERT INTO demo_effects(operation_id,target,old_version,new_version,value) VALUES(?,?,?,?,?)",
                       (self.request_id, OPERATION["target"], 0, 1, 1))
            row["target_staged"] = True
            self.record(row)
            if self.fault == "before_commit":
                os._exit(73)
            return
        self.record(row)
        if kind == "tx_commit" and data.get("operation") == "finish" and self.fault == "after_commit":
            os._exit(73)

    def handle(self, uid, raw):
        role = self.roles.get(uid)
        if role is None:
            return {"code": "BLOCK_ROLE"}
        try:
            req = loads(raw)
            op = req.get("op") if type(req) is dict else None
            if op == "propose":
                if role != "requester":
                    return {"code": "BLOCK_ROLE"}
                shape(req, ("op", *OPERATION.keys()))
                actual = {key: req[key] for key in OPERATION}
                if any(type(actual[k]) is not type(v) or actual[k] != v for k, v in OPERATION.items()):
                    return {"code": "BLOCK_DEMO_OPERATION"}
                return super().handle(uid, canonical({"op": "prepare", "request_id": self.request_id,
                                                      "action": "COAST"}))
            if op == "prepare":
                return {"code": "BLOCK_DEMO_OPERATION"}
            if op == "fixture_conditions":
                if role != "maintainer":
                    return {"code": "BLOCK_ROLE"}
                shape(req, ("op", "healthy"))
                if type(req["healthy"]) is not bool:
                    return {"code": "BLOCK_INPUT"}
                self.conditions = ((True,) * 5 if req["healthy"] else (False, True, True, True, True))
                return {"code": "FIXTURE_CONDITIONS_SET"}
        except (TypeError, ValueError, KeyError):
            return {"code": "BLOCK_INPUT"}
        return super().handle(uid, raw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runtime", type=Path)
    ap.add_argument("--journal", required=True, type=Path)
    ap.add_argument("--fault", choices=("none", "before_commit", "after_commit"), default="none")
    args = ap.parse_args()
    service = SqlDemoService(args.runtime, journal=args.journal, fault=args.fault)
    service.serve()


if __name__ == "__main__":
    main()
