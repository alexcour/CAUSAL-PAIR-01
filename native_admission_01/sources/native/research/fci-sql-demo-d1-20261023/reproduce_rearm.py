"""Actual UID/IPC D1 campaign. Witnesses remain trusted fixture evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from sql_rearm_service import SCHEMA, IDS, OPERATION
from reproduce import Fixture as D0Fixture, save, SUID, RUID, MUID, OTHER, FROZEN

D0_COMMIT = "ccb5db2604581f2f2831ecf2ded9c19430159e94"
CLAIMS = {"qualification": "HOLD/OPEN", "NONLEAK_END_TO_END": False,
          "physical_tests": "NOT_RUN", "full_P01_P14": "NOT_COMPLETE",
          "independent_third_party_replay": "NOT_RUN"}


def source_paths():
    manifest = json.loads((HERE / "SOURCE_FREEZE.json").read_text())
    return sorted([f["path"] for f in manifest["files"]] +
                  [str(p.relative_to(ROOT)) for p in HERE.iterdir()
                   if p.is_file() and (p.suffix == ".py" or p.name == "SOURCE_FREEZE.json")])


class Fixture(D0Fixture):
    def __init__(self, parent, name):
        self.phase = "provisioning"
        self.checkpoints = []
        self.process_receipts = []
        super().__init__(parent, name)

    def start(self, fault="none"):
        if fault != "none":
            raise ValueError("D1 does not expose process-cut options")
        self.process = subprocess.Popen(
            [sys.executable, str(HERE / "sql_rearm_service.py"), str(self.runtime),
             "--journal", str(self.journal)], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            user=SUID, group=SUID, extra_groups=[])
        ready, _, _ = select.select([self.process.stdout], [], [], 10)
        line = self.process.stdout.readline() if ready else ""
        if not line.startswith("READY "):
            self.process.kill()
            _, err = self.process.communicate(timeout=5)
            raise RuntimeError("D1 startup failed: " + err)
        self.process_receipts.append({"pid": self.process.pid, "requested_uid": SUID,
                                      "started_monotonic_ns": time.monotonic_ns()})

    def call(self, req, uid=RUID, drop=False):
        result = super().call(req, uid, drop)
        rid = req.get("operation_id", req.get("request_id"))
        if req.get("op") == "deliver":
            rid = req["ticket"]["token"]["body"]["request_id"]
        self.calls[-1].update(phase=self.phase, request_id=rid)
        return result

    def observe(self):
        observed = super().observe()
        with sqlite3.connect(f"file:{self.runtime}/consumer.db?mode=ro", uri=True) as db:
            state = json.loads(db.execute("SELECT payload FROM consumer WHERE id=1").fetchone()[0])
            entries = []
            for rid, payload in db.execute("SELECT request_id,payload FROM inbox ORDER BY request_id"):
                entry = json.loads(payload)
                entries.append({"request_id": rid, "status": entry["status"],
                                "delivery_epoch": entry["delivery"]["epoch"],
                                "eligible": entry["delivery"]["eligible"]})
            audits = db.execute("SELECT COUNT(*) FROM rearm_audit").fetchone()[0]
        stat = (self.runtime / "consumer.db").stat()
        return {**observed, "consumer_epoch": state["epoch"],
                "consumer_revision": state["revision"], "authority_floor": state["authority_floor"],
                "entries": entries, "rearm_audit_count": audits,
                "target_database_identity": {"device": stat.st_dev, "inode": stat.st_ino}}

    def checkpoint(self, label):
        self.checkpoints.append({"label": label, "call_count": len(self.calls),
                                 "service_pid": self.process.pid,
                                 "monotonic_ns": time.monotonic_ns(), "state": self.observe()})
        self.phase = label

    def delivered_id(self, rid):
        result = self.call({"op": "propose", **OPERATION, "operation_id": rid})
        assert "ticket" in result, result
        ticket = result["ticket"]
        result = self.call({"op": "deliver", "ticket": ticket})
        assert result["code"] == "DELIVERED", result
        return ticket

    def finish_id(self, rid):
        return self.call({"op": "finish", "request_id": rid})


def blocked(result):
    assert result["code"].startswith("BLOCK_") and result.get("new_effect") is False, result


def latch(f):
    old = f.delivered_id("CFG001")
    f.call({"op": "fixture_conditions", "healthy": False}, MUID)
    blocked(f.finish_id("CFG001"))
    assert f.observe()["mask"] & 1
    f.checkpoint("latched")
    f.call({"op": "fixture_conditions", "healthy": True}, MUID)
    for _ in range(10):
        blocked(f.finish_id("CFG001"))
    f.checkpoint("healthy_latched")
    return old


def fresh_after_rearm(f):
    old = latch(f)
    f.stop()
    f.start()
    assert f.observe()["mask"] & 1
    f.checkpoint("restart_latched")
    assert f.call({"op": "rearm_local", "witness": {}})["code"] == "BLOCK_ROLE"
    assert f.call({"op": "rearm_local", "witness": {}}, MUID)["code"].startswith("BLOCK_")
    assert f.observe()["mask"] & 1
    f.checkpoint("invalid_rearm_refused")
    f.commission()
    assert f.observe()["mask"] == 0
    f.checkpoint("rearmed")
    assert f.call({"op": "deliver", "ticket": old})["new_effect"] is False
    assert f.finish_id("CFG001") == {"code": "BLOCK_LOCAL_FENCE", "new_effect": False}
    f.checkpoint("old_refused_after_rearm")
    f.delivered_id("CFG002")
    assert f.finish_id("CFG002") == {"code": "EFFECT_COMMITTED", "new_effect": True}
    f.checkpoint("fresh_effect")
    blocked(f.finish_id("CFG001"))
    assert f.finish_id("CFG002") == {"code": "ACK_EFFECT_HISTORY", "new_effect": False}
    f.checkpoint("both_replayed")
    f.stop()
    f.start()
    assert f.finish_id("CFG002") == {"code": "ACK_EFFECT_HISTORY", "new_effect": False}
    blocked(f.finish_id("CFG001"))
    f.checkpoint("history_after_restart")
    assert f.observe()["effects"] == [("CFG002", "synthetic-config", 0, 1, 1)]
    return ["same persistent target, no reprovisioning or SQL repair between fault and fresh effect",
            "explicit valid maintainer rearm precedes fresh CFG002; stale CFG001 stays fenced",
            "only CFG002 mutates once; old/new replay and second real restart add no effect"]


def fresh_before_rearm(f):
    latch(f)
    result = f.call({"op": "propose", **OPERATION, "operation_id": "CFG002"})
    assert "ticket" in result, result
    assert f.call({"op": "deliver", "ticket": result["ticket"]})["code"] == "DELIVERY_QUARANTINED"
    blocked(f.finish_id("CFG002"))
    f.checkpoint("fresh_quarantined_before_rearm")
    f.commission()
    assert f.observe()["mask"] == 0
    f.checkpoint("rearmed")
    for rid in IDS:
        assert f.finish_id(rid) == {"code": "BLOCK_LOCAL_FENCE", "new_effect": False}
    f.checkpoint("quarantined_ids_stay_fenced")
    assert not f.observe()["effects"]
    return ["new ID alone cannot bypass a persistent latch",
            "rearm does not rehabilitate an entry received while latched"]


def scope_and_roles(f):
    for patch in ({"operation_id": "CFG003"}, {"value": 0}, {"expected_version": True},
                  {"target": "other"}):
        assert f.call({"op": "propose", **OPERATION, **patch})["code"] == "BLOCK_DEMO_OPERATION"
    assert f.call({"op": "propose", **OPERATION}, MUID)["code"] == "BLOCK_ROLE"
    assert f.call({"op": "status"}, OTHER)["code"] == "BLOCK_ROLE"
    assert f.call({"op": "prepare", "request_id": "CFG002", "action": "COAST"})["code"] == "BLOCK_DEMO_OPERATION"
    assert f.call({"op": "finish", "request_id": "CFG003"})["code"] == "BLOCK_DEMO_OPERATION"
    f.checkpoint("scope_refusals")
    f.delivered_id("CFG001")
    assert f.finish_id("CFG001") == {"code": "EFFECT_COMMITTED", "new_effect": True}
    assert f.finish_id("CFG001") == {"code": "ACK_EFFECT_HISTORY", "new_effect": False}
    f.checkpoint("original_id_nominal")
    assert f.observe()["effects"] == [("CFG001", "synthetic-config", 0, 1, 1)]
    return ["two-ID facade retains fixed target, strict parameter types and role boundaries",
            "original CFG001 nominal path still works on this D1 candidate"]


def campaign(out):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("NOT_RUN_ENVIRONMENT: disposable Linux root controller required")
    for mapping in ("uid_map", "gid_map"):
        ranges = [tuple(map(int, line.split())) for line in Path("/proc/self/" + mapping).read_text().splitlines()]
        if not all(any(start <= uid < start + length for start, _, length in ranges)
                   for uid in (SUID, RUID, MUID, OTHER)):
            raise RuntimeError("NOT_RUN_ENVIRONMENT: distinct experimental UIDs are not mapped; use Linux CI")
    out.mkdir(parents=True, exist_ok=False)
    cases = []
    with tempfile.TemporaryDirectory(prefix="fci-sql-d1-") as tmp:
        parent = Path(tmp)
        os.chmod(parent, 0o755)
        for name, fn in (("REARM_THEN_FRESH_OPERATION", fresh_after_rearm),
                         ("FRESH_ID_BEFORE_REARM_REFUSED", fresh_before_rearm),
                         ("SCOPE_AND_ROLE_REFUSALS", scope_and_roles)):
            f = Fixture(parent, name)
            try:
                initial = f.observe()
                f.commission()
                f.checkpoint("commissioned")
                findings = fn(f)
                case = {"id": name, "status": "PASS_EXECUTED_SCOPED", "initial": initial,
                        "final": f.observe(), "checkpoints": f.checkpoints, "calls": f.calls,
                        "events": [json.loads(line) for line in f.journal.read_text().splitlines()],
                        "peer_receipts": f.peer_receipts, "process_receipts": f.process_receipts,
                        "findings": findings}
                cases.append(case)
                save(out / (name + ".json"), case)
            except BaseException as error:
                save(out / (name + ".json"), {"id": name, "status": "FAIL_EXECUTED",
                     "error_type": type(error).__name__, "error": str(error),
                     "calls": f.calls, "checkpoints": f.checkpoints, "observed": f.observe(),
                     "events": [json.loads(line) for line in f.journal.read_text().splitlines()],
                     "peer_receipts": f.peer_receipts, "process_receipts": f.process_receipts})
                raise
            finally:
                f.close()
    receipt = {"schema": SCHEMA, "status": "PASS_EXECUTED_SCOPED", "case_count": len(cases),
               "executed_utc": datetime.now(timezone.utc).isoformat(),
               "reference_commit": FROZEN, "d0_dependency_commit": D0_COMMIT,
               "controller_uid": os.geteuid(), "service_uid": SUID,
               "requester_uid": RUID, "maintainer_uid": MUID,
               "python": platform.python_version(), "platform": platform.platform(),
               "cases": cases, "global_claims": CLAIMS,
               "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in source_paths()}}
    save(out / "RESULTS.json", receipt)
    print(json.dumps({"status": receipt["status"], "cases": len(cases), "results": str(out / "RESULTS.json")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    campaign(parser.parse_args().output)
