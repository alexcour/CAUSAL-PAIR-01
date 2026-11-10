"""D1: two allowlisted IDs, one fixed SQL transition, serialized IPC only.

This new entrypoint selects REF4's request scope under its existing entry lock.
It does not change a frozen consumer or transfer REF4/D0 qualification to D1.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "fci-sql-demo-20261022"))
from adapter import OPERATION, SqlDemoService
from integrated_service import IntegratedService
from fci_hardened.strict_json import canonical, loads, shape

SCHEMA = "FCI-SQL-DEMO-D1/1"
IDS = ("CFG001", "CFG002")


class SqlRearmService(SqlDemoService):
    def record(self, row):
        with self.journal.open("a", encoding="utf-8") as out:
            out.write(json.dumps({"schema": SCHEMA, "uid": os.geteuid(),
                                  "request_id": self.request_id,
                                  "monotonic_ns": time.monotonic_ns(), **row}, sort_keys=True) + "\n")
            out.flush()
            os.fsync(out.fileno())

    def _dispatch(self, op, req):
        result = super()._dispatch(op, req)
        if op == "status":
            result = {**result, "candidate": SCHEMA, "admitted_operation_ids": list(IDS)}
        return result

    def handle(self, uid, raw):
        role = self.roles.get(uid)
        if role is None:
            return {"code": "BLOCK_ROLE"}
        if threading.get_ident() != self._owner_thread:
            return {"code": "BLOCK_REF4_THREAD"}
        try:
            req = loads(raw)
            if type(req) is not dict:
                return {"code": "BLOCK_INPUT"}
            op = req.get("op")
            if op == "propose":
                if role != "requester":
                    return {"code": "BLOCK_ROLE"}
                shape(req, ("op", *OPERATION.keys()))
                rid = req["operation_id"]
                if type(rid) is not str or rid not in IDS:
                    return {"code": "BLOCK_DEMO_OPERATION"}
                for key, value in OPERATION.items():
                    if key != "operation_id" and (type(req[key]) is not type(value) or req[key] != value):
                        return {"code": "BLOCK_DEMO_OPERATION"}
                forwarded = canonical({"op": "prepare", "request_id": rid, "action": "COAST"})
            elif op in ("finish", "inspect"):
                rid = req.get("request_id")
                forwarded = raw
            elif op == "deliver":
                rid = req["ticket"]["token"]["body"]["request_id"]
                forwarded = raw
            elif op == "prepare":
                return {"code": "BLOCK_DEMO_OPERATION"}
            else:
                # D0 still owns the fixture-only condition setter; all other
                # operations retain its role checks and the original service.
                return super().handle(uid, raw)
            if type(rid) is not str or rid not in IDS:
                return {"code": "BLOCK_DEMO_OPERATION"}
        except (KeyError, TypeError, ValueError):
            return {"code": "BLOCK_INPUT"}
        with self._entry_lock:
            if self._active_request:
                return {"code": "BLOCK_REF4_REENTRANT"}
            previous = self.request_id
            self.request_id = rid
            try:
                return IntegratedService.handle(self, uid, forwarded)
            finally:
                self.request_id = previous


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runtime", type=Path)
    ap.add_argument("--journal", type=Path, required=True)
    args = ap.parse_args()
    SqlRearmService(args.runtime, journal=args.journal).serve()


if __name__ == "__main__":
    main()
