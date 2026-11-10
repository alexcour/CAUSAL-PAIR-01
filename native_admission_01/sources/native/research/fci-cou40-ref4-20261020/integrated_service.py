"""REF4 research entrypoint: LIFE01/RC3/REF3 composed at service opening.

The original Service constructor performs the non-root UID checks, signed
PolicyPack verification and exclusive lifetime flock.  This class changes the
explicit consumer construction in _open_state, never an already-open consumer.
The default additional check reuses BOTH arguments supplied to finish, including
the action-bound observer conditions selected by Service._dispatch.

The supported entry is one fixed request ID, fixed policy, and the thread that
opened SQLite.  Direct component access by the trusted service UID is outside
the entrypoint contract.  No actuator, rollback root or transport guarantee is
added.  Event callbacks and alternative provider factories are trusted research
instrumentation; the command-line entrypoint exposes neither to a client.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import asdict
import hashlib
import hmac
from pathlib import Path
import re
import sqlite3
import sys
import threading

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / "fci-c02-a04-20261018"
REF3 = HERE.parent / "fci-cou40-ref3-20261020"
sys.path.insert(0, str(REFERENCE))
sys.path.insert(0, str(REF3))

from composition_runtime import CompositionConsumer, Recheck, encode_observation
from fci_hardened.observation import Observation
from fci_hardened.service import (CONTEXT, KEY_NAMES, ROLE_OPS, Service, protected_file,
                                  request_id as validate_request_id)
from fci_hardened.spend_ledger import SpendLedger, ticket_digest
from fci_hardened.strict_json import loads, shape
from fci_hardened.vendor import DispatchAuthority, SQLiteSinkAnchor
from lifecycle import REARM_DOMAIN, canonical, mac

VERSION = "FCI-COU40-REF4-INTEGRATED/1"
DEFAULT_REQUEST_ID = "REF4_ONE"


def normal_revalidation(clock, conditions):
    """Preserve the exact action-dependent conditions supplied by Service."""
    return (Recheck("service_entry_revalidation", clock, conditions),)


class RecordingAnchor(SQLiteSinkAnchor):
    """Read observer; every value is obtained from the original _read."""
    def __init__(self, *args, record_source, **kwargs):
        self._record_source = record_source
        super().__init__(*args, **kwargs)

    def _read(self):
        result = super()._read()
        self._record_source(result, self.target)
        return result


class RecordingSpendLedger(SpendLedger):
    def __init__(self, *args, emit, **kwargs):
        self._emit = emit
        super().__init__(*args, **kwargs)

    def reserve(self, rid, ticket, kind, revision):
        # The original method owns BEGIN/UPDATE/COMMIT and its failure paths.
        result = super().reserve(rid, ticket, kind, revision)
        if result:
            self._emit("reserve", {"request_id": rid, "ticket_digest": ticket_digest(ticket),
                                   "kind": kind, "consumer_revision": revision},
                       {"source": "SpendLedger.reserve returned after its real COMMIT",
                        "result": result, "ledger_in_transaction": self.db.in_transaction})
        return result


class IntegratedConsumer(CompositionConsumer):
    def __init__(self, *args, emit, revalidation_factory=normal_revalidation, **kwargs):
        if "_startup" in kwargs:
            raise TypeError("the integrated entrypoint always performs normal startup")
        if not callable(revalidation_factory):
            raise TypeError("trusted revalidation factory required")
        self._emit = emit
        self._revalidation_factory = revalidation_factory
        self._capture_context = None
        super().__init__(*args, **kwargs)

    def record_source_read(self, state, target):
        if self._capture_context is not None:
            self._capture_context["source_read"] = {"state": asdict(state), "target": target}

    def _source(self, anchor, ticket):
        good, state = super()._source(anchor, ticket)
        if self._capture_context is not None:
            self._capture_context["source"] = {
                "good": bool(good), "revision": state.revision if state is not None else None}
        return good, state

    def _load(self, table, ident, value, domain):
        result = super()._load(table, ident, value, domain)
        if table == "rearm_audit" and self._capture_context is not None:
            self._capture_context["audit_lookup"] = {"witness_id": value, "hit": result is not None,
                                                       "authenticated_read": True}
        return result

    def receive(self, ticket, anchor, now=100, hook=None):
        self._capture_context = {"operation": "receive", "now": now, "source": None}
        try:
            return super().receive(ticket, anchor, now, hook)
        finally:
            self._capture_context = None

    def rearm(self, flags, witness, anchor, now=100, hook=None):
        self._capture_context = {"operation": "rearm", "flags": list(flags), "now": now,
                                 "witness": copy.deepcopy(witness)}
        try:
            return super().rearm(flags, witness, anchor, now, hook)
        finally:
            self._capture_context = None

    def finish(self, rid, anchor, clock, conditions, hook=None):
        context = {"operation": "finish", "times": [], "flags": [], "source": None}
        self._capture_context = context

        def measured_clock():
            value = clock()
            context["times"].append(value)
            return value

        def measured_conditions():
            value = conditions()
            # Capture the original REF3 normalization without replacing its
            # input or making non-iterable malformed inputs raise here.
            context["flags"].append(list(encode_observation(value).flags))
            return value

        def measured_check(check):
            def checked(provider, component):
                def invoke():
                    try:
                        return provider()
                    except Exception as error:
                        context["provider_failed_before_commit"] = True
                        self._emit("provider_exception", {"where": "late_fence"},
                                   {"source": "trusted additional provider actually raised",
                                    "provider": check.name, "component": component,
                                    "exception_type": type(error).__name__, "message": str(error)})
                        raise
                return invoke
            return Recheck(check.name, checked(check.clock, "clock"),
                           checked(check.conditions, "conditions"))

        try:
            plan = self._revalidation_factory(clock, conditions)
            if type(plan) is not tuple or any(type(check) is not Recheck for check in plan):
                raise TypeError("trusted factory must return an exact tuple of Recheck")
            checks = tuple(measured_check(check) for check in plan)
            return super().finish(rid, anchor, measured_clock, measured_conditions, hook, rechecks=checks)
        finally:
            self._capture_context = None

    def _stage_input(self, operation):
        context = self._capture_context
        if context is None or context["operation"] != operation:
            raise RuntimeError("operation is outside the REF4 trace domain")
        if operation == "receive":
            return {"operation": operation, "now": context["now"], "source": context["source"]}
        if operation == "finish":
            if len(context["times"]) != len(context["flags"]):
                raise RuntimeError("initial LIFE01 sampling structure changed")
            return {"operation": operation,
                    "samples": [{"now": now, "flags": flags}
                                for now, flags in zip(context["times"], context["flags"])],
                    "source": context["source"]}
        if operation == "rearm":
            witness = context["witness"]
            try:
                authenticated = (type(witness["signature"]) is str and hmac.compare_digest(
                    witness["signature"], mac(self.rearm_key, REARM_DOMAIN, witness["body"])))
            except (KeyError, ValueError, TypeError):
                authenticated = False
            source = context.get("source_read")
            local = self._state()
            revision = (source["state"]["revision"] if source is not None
                        and source["state"]["instance"] == local.instance
                        and source["target"] == local.target else None)
            return {"operation": operation, "flags": context["flags"], "now": context["now"],
                    "witness_id": hashlib.sha256(canonical(witness)).hexdigest(),
                    "witness": witness, "mac_verified": authenticated, "source_revision": revision}
        raise RuntimeError("unsupported traced consumer transaction")

    def _transaction(self, operation, fn, hook=None, anchor=None):
        began = False
        committed = False
        before_rows = None

        def logical_rows(connection):
            return {table: connection.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall()
                    for table in ("consumer", "inbox", "commit_fence", "rearm_audit")}

        def inside(point):
            nonlocal began, before_rows
            began = True
            before_rows = logical_rows(self.db)
            self._emit("tx_begin", {"operation": operation},
                       {"source": "wrapped fn entered after original BEGIN IMMEDIATE",
                        "consumer_in_transaction": self.db.in_transaction})
            result = fn(point)
            self._emit("tx_stage", self._stage_input(operation),
                       {"source": "original transaction fn returned before after_write hook",
                        "result_code": result.code, "result_new_effect": result.new_effect,
                        "result_origin": "LIFE01_FN_RESULT_BEFORE_COMMIT",
                        "audit_lookup": (self._capture_context or {}).get("audit_lookup"),
                        "source_read": (self._capture_context or {}).get("source_read")})
            return result

        def traced_hook(point):
            nonlocal committed
            if point == operation + "_after_commit":
                committed = True
                self._emit("tx_commit", {"operation": operation},
                           {"source": "original transaction after_commit hook",
                            "consumer_in_transaction": self.db.in_transaction})
            if hook is not None:
                hook(point)

        result = super()._transaction(operation, inside, traced_hook, anchor)
        if began and not committed:
            if self.db.in_transaction:
                raise RuntimeError("transaction returned without a resolved SQLite transaction")
            # Missing after_commit alone does NOT establish rollback.  The
            # bounded REF4 exception path is an observed provider exception in
            # the pre-COMMIT hook.  Ambiguous COMMIT outcomes remain outside
            # this alphabet, even if SQLite no longer reports a transaction.
            if (not (self._capture_context or {}).get("provider_failed_before_commit")
                    or result.code != "BLOCK_STORAGE"):
                raise RuntimeError("unclassified transaction outcome; no rollback event inferred")
            database = next(row[2] for row in self.db.execute("PRAGMA database_list") if row[1] == "main")
            connection = sqlite3.connect(database, isolation_level=None)
            try:
                unchanged = logical_rows(connection) == before_rows
            finally:
                connection.close()
            if not unchanged:
                raise RuntimeError("pre-COMMIT failure has a different durable readback")
            self._emit("tx_rollback", {"operation": operation},
                       {"source": "observed pre-COMMIT provider exception, original rollback path and independent SQL readback",
                        "result_code": result.code, "consumer_in_transaction": False,
                        "consumer_sql_rows_equal_to_begin": unchanged})
        return result

    def _run_original_finalizer(self, index, *args):
        verdict = super()._run_original_finalizer(index, *args)
        row = self.last_trace["finalizers"][-1]
        self._emit("late_fence", {**row["input"], "flags": row["fence"]["flags"],
                                  "source_revision": row["fence"]["source_revision"]},
                   {"source": "REF3 wrapper returned from the original RC3 _finalize",
                    "index": index, "result_code": verdict, "result_origin": "RC3_FINALIZER_RETURN_BEFORE_COMMIT",
                    "capture": row, "normalization_observations": self.last_trace["observations"]})
        return verdict

    def _replace_owned_fence(self, rid):
        super()._replace_owned_fence(rid)
        self._emit("fence_remove", {},
                   {"source": "REF3 replaced only its owned, uncommitted PASS fence",
                    "request_id": rid, "removed": self.last_trace["removed_uncommitted_fences"][-1]})


class IntegratedService(Service):
    """Launchable research Service with a constructor-bound consumer class."""
    def __init__(self, runtime, *, request_id=DEFAULT_REQUEST_ID, event_hook=None,
                 revalidation_factory=normal_revalidation):
        self.request_id = validate_request_id(request_id)
        self._event_hook = event_hook
        self._revalidation_factory = revalidation_factory
        self._owner_thread = threading.get_ident()
        self._entry_lock = threading.RLock()
        self._active_request = False
        self.ref4_opened = False
        super().__init__(runtime)
        self.ref4_opened = True
        self._emit("startup", {}, {"source": "IntegratedService.__init__ successfully returned from Service.__init__",
                                    "code_origin": "NO_CONSTRUCTOR_RETURN_CODE",
                                    "consumer_class": type(self.consumer).__name__,
                                    "normal_startup": True})

    def _emit(self, kind, data, raw=None):
        if self._event_hook is not None:
            self._event_hook(kind, copy.deepcopy(data), copy.deepcopy(raw or {}), self)

    def _record_source(self, state, target):
        consumer = getattr(self, "consumer", None)
        if consumer is not None:
            consumer.record_source_read(state, target)

    def _open_state(self):
        """Exact original opening checks; explicit integrated classes at creation."""
        keys = shape(loads(protected_file(self.runtime / "keys.json")), KEY_NAMES)
        if any(type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value) for value in keys.values()):
            raise ValueError("key encoding")
        k = {name: bytes.fromhex(value) for name, value in keys.items()}
        if len(set(k.values())) != len(KEY_NAMES):
            raise ValueError("distinct keys")
        for filename in ("anchor.db", "replica.db", "consumer.db", "spend.db"):
            protected_file(self.runtime / filename, metadata_only=True)
        self.anchor = RecordingAnchor(self.runtime / "anchor.db", k["anchor"], "I", k["token"], k["receipt"],
                                      record_source=self._record_source)
        self.authority = DispatchAuthority(self.runtime / "replica.db", k["state"], k["rearm"], "I", self.anchor)
        self.spend = RecordingSpendLedger(self.runtime / "spend.db", k["spend"],
                                          {"instance": "I", "target": "SIM_SINK", "policy": self.policy.digest,
                                           "context": CONTEXT}, emit=self._emit)
        self.consumer = IntegratedConsumer(self.runtime / "consumer.db", k["effect"], k["token"], k["receipt"],
                                            k["local_rearm"], ledger=self.spend, emit=self._emit,
                                            revalidation_factory=self._revalidation_factory)
        a, c = self.authority.state(), self.consumer._state()
        if (a.policy, a.context, c.policy, c.context) != (self.policy.digest, CONTEXT, self.policy.digest, CONTEXT):
            raise ValueError("policy/state binding; explicit migration required")
        self.observation = Observation(self.policy)
        self.conditions = tuple(self.policy.body["fixture"]["conditions"])
        self.levels = self.policy.body["action_levels"]
        self.poisoned = False

    def _dispatch(self, op, req):
        result = super()._dispatch(op, req)
        if op == "status":
            result = dict(result)
            result["reference_candidate"] = result["candidate"]
            result["candidate"] = VERSION
            result["entrypoint"] = type(self).__name__
        return result

    def handle(self, uid, raw):
        if uid not in self.roles:
            return super().handle(uid, raw)
        if threading.get_ident() != self._owner_thread:
            return {"code": "BLOCK_REF4_THREAD"}
        with self._entry_lock:
            if self._active_request:
                return {"code": "BLOCK_REF4_REENTRANT"}
            try:
                req = loads(raw)
            except Exception:
                return super().handle(uid, raw)
            if type(req) is dict:
                op = req.get("op")
                if type(op) is not str or op not in ROLE_OPS[self.roles[uid]]:
                    return super().handle(uid, raw)
                if self.poisoned:
                    # Keep Service's poison priority. A supported, well-shaped
                    # attempted finish may still be captured as a call, with
                    # no implication that a consumer transaction begins.
                    try:
                        shape(req, ("op", "request_id"))
                        admitted_poison_call = (op == "finish" and req["request_id"] == self.request_id)
                    except (ValueError, TypeError):
                        admitted_poison_call = False
                    if admitted_poison_call:
                        self._emit("call_begin", {"op": op}, {"source": "well-shaped call rejected by Service poison gate",
                                                                "uid": uid, "request": req})
                    return super().handle(uid, raw)
                if op in ("cancel", "fixture_observe"):
                    return {"code": "BLOCK_REF4_SCOPE"}
                if op in ("prepare", "finish", "inspect"):
                    try:
                        candidate_id = validate_request_id(req.get("request_id"))
                    except (ValueError, TypeError):
                        return super().handle(uid, raw)
                    if candidate_id != self.request_id:
                        return {"code": "BLOCK_REF4_SCOPE"}
                if op == "deliver":
                    try:
                        if req["ticket"]["token"]["body"]["request_id"] != self.request_id:
                            return {"code": "BLOCK_REF4_SCOPE"}
                    except (KeyError, TypeError):
                        pass  # The original strict parser decides malformed input.
            else:
                op = None
            self._active_request = True
            try:
                if op in ("rearm_local", "deliver", "finish"):
                    try:
                        expected_keys = {"rearm_local": ("op", "witness"), "deliver": ("op", "ticket"),
                                         "finish": ("op", "request_id")}[op]
                        shape(req, expected_keys)
                        if op == "finish":
                            validate_request_id(req["request_id"])
                    except (ValueError, TypeError):
                        return super().handle(uid, raw)
                    self._emit("call_begin", {"op": op}, {"source": "role-admitted and well-shaped IntegratedService.handle call",
                                                            "uid": uid, "request": req})
                return super().handle(uid, raw)
            finally:
                self._active_request = False

    def close(self):
        import os
        for name in ("consumer", "spend", "authority", "anchor"):
            item = getattr(self, name, None)
            if item is not None:
                item.close()
        if hasattr(self, "lock_fd"):
            os.close(self.lock_fd)
            del self.lock_fd
        self.ref4_opened = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--request-id", default=DEFAULT_REQUEST_ID)
    args = parser.parse_args()
    service = IntegratedService(args.runtime, request_id=args.request_id)
    print("ENTRYPOINT " + VERSION, flush=True)
    service.serve()


if __name__ == "__main__":
    main()
