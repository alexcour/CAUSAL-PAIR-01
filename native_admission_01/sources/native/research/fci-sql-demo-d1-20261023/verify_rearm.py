"""Separate D1 receipt checker, by the same author; not a third-party audit."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED = {"REARM_THEN_FRESH_OPERATION": "CFG002", "FRESH_ID_BEFORE_REARM_REFUSED": None,
            "SCOPE_AND_ROLE_REFUSALS": "CFG001"}
LABELS = {
    "REARM_THEN_FRESH_OPERATION": ["commissioned", "latched", "healthy_latched", "restart_latched",
        "invalid_rearm_refused", "rearmed", "old_refused_after_rearm", "fresh_effect",
        "both_replayed", "history_after_restart"],
    "FRESH_ID_BEFORE_REARM_REFUSED": ["commissioned", "latched", "healthy_latched",
        "fresh_quarantined_before_rearm", "rearmed", "quarantined_ids_stay_fenced"],
    "SCOPE_AND_ROLE_REFUSALS": ["commissioned", "scope_refusals", "original_id_nominal"]}
CLAIMS = {"qualification": "HOLD/OPEN", "NONLEAK_END_TO_END": False,
          "physical_tests": "NOT_RUN", "full_P01_P14": "NOT_COMPLETE",
          "independent_third_party_replay": "NOT_RUN"}


def require(value, message):
    if not value:
        raise ValueError(message)


def target(state, rid):
    count = int(rid is not None)
    require(state["configuration"] == [["synthetic-config", count, count]], "target version/value")
    expected = [] if rid is None else [[rid, "synthetic-config", 0, 1, 1]]
    require(state["effects"] == expected, "target effect identity/count")
    require(state["observer"] == "DISTINCT_READ_ONLY_SQLITE_CONNECTION_PRIVILEGED_CONTROLLER", "target oracle")


def entry(state, rid):
    matches = [e for e in state["entries"] if e["request_id"] == rid]
    require(len(matches) == 1, "missing or duplicated inbox entry")
    return matches[0]


def verify(receipt, root):
    require(receipt["schema"] == "FCI-SQL-DEMO-D1/1", "schema")
    require(receipt["status"] == "PASS_EXECUTED_SCOPED" and receipt["case_count"] == 3, "incomplete execution")
    require(receipt["global_claims"] == CLAIMS, "scope promotion")
    require(receipt["reference_commit"] == "7a0784a4dc8d9953487ebeb54bd42df834d40eb4" and
            receipt["d0_dependency_commit"] == "ccb5db2604581f2f2831ecf2ded9c19430159e94", "base identity")
    require([receipt[k] for k in ("controller_uid", "service_uid", "requester_uid", "maintainer_uid")] ==
            [0, 61051, 61052, 61053], "role provenance")
    manifest_path = HERE.relative_to(HERE.parents[1]) / "SOURCE_FREEZE.json"
    manifest = json.loads((root / manifest_path).read_text())
    expected_paths = {f["path"] for f in manifest["files"]} | {
        str(manifest_path.parent / p.name) for p in HERE.iterdir()
        if p.is_file() and (p.suffix == ".py" or p.name == "SOURCE_FREEZE.json")}
    require(set(receipt["source_sha256"]) == expected_paths, "incomplete source set")
    for path, digest in receipt["source_sha256"].items():
        require(not Path(path).is_absolute() and ".." not in Path(path).parts, "source path")
        require(hashlib.sha256((root / path).read_bytes()).hexdigest() == digest, "source changed: " + path)
    for frozen in manifest["files"]:
        data = (root / frozen["path"]).read_bytes()
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() ==
                frozen["git_blob_sha"], "frozen dependency changed")
    require(len(receipt["cases"]) == 3 and {c["id"] for c in receipt["cases"]} == set(EXPECTED), "case identity")
    cases = {c["id"]: c for c in receipt["cases"]}
    for name, rid in EXPECTED.items():
        case = cases[name]
        require(case["status"] == "PASS_EXECUTED_SCOPED", "case status")
        target(case["initial"], None)
        target(case["final"], rid)
        require([p["label"] for p in case["checkpoints"]] == LABELS[name], "checkpoint order")
        checkpoints = case["checkpoints"]
        require(all(a["call_count"] <= b["call_count"] and a["monotonic_ns"] <= b["monotonic_ns"]
                    for a, b in zip(checkpoints, checkpoints[1:])), "checkpoint chronology")
        require(all(p["call_count"] <= len(case["calls"]) for p in checkpoints), "checkpoint call bounds")
        identity = case["initial"]["target_database_identity"]
        require(all(p["state"]["target_database_identity"] == identity for p in checkpoints) and
                case["final"]["target_database_identity"] == identity, "target replacement")
        require(case["events"] and all(e["uid"] == 61051 and e["schema"] == receipt["schema"]
                                       for e in case["events"]), "real service UID")
        peers = {p["peer_uid"] for p in case["peer_receipts"]}
        require({61052, 61053} <= peers <= {61052, 61053, 61054}, "real peer UIDs")
        require(all(c["uid"] in peers for c in case["calls"]), "unattested peer")
        require(all(c["completed_monotonic_ns"] >= c["started_monotonic_ns"] for c in case["calls"]), "call clocks")
        require(all(p["requested_uid"] == 61051 for p in case["process_receipts"]), "process role")
        done = False
        for point in checkpoints:
            done = done or point["label"] in ("fresh_effect", "original_id_nominal")
            target(point["state"], rid if done else None)
        staged = [e for e in case["events"] if e.get("target_staged")]
        require([e["request_id"] for e in staged] == ([] if rid is None else [rid]), "SQL stage attribution")
    case = cases["REARM_THEN_FRESH_OPERATION"]
    points = {p["label"]: p for p in case["checkpoints"]}
    for label in ("latched", "healthy_latched", "restart_latched", "invalid_rearm_refused"):
        require(points[label]["state"]["mask"] & 1, "latch disappeared")
    rearmed = points["rearmed"]["state"]
    require(rearmed["mask"] == 0 and rearmed["rearm_audit_count"] >
            points["invalid_rearm_refused"]["state"]["rearm_audit_count"], "no durable explicit rearm")
    require(entry(rearmed, "CFG001")["delivery_epoch"] < rearmed["consumer_epoch"], "old epoch revived")
    fresh = points["fresh_effect"]["state"]
    require(entry(fresh, "CFG002")["eligible"] is True and entry(fresh, "CFG002")["status"] == "DONE" and
            entry(fresh, "CFG002")["delivery_epoch"] == rearmed["consumer_epoch"], "fresh authorization epoch")
    calls = case["calls"]
    a = points["invalid_rearm_refused"]["call_count"]
    b = points["rearmed"]["call_count"]
    require(any(c["op"] == "rearm_local" and c["uid"] == 61053 and
                c["response"]["code"] == "REARM_LOCAL_ACCEPTED" for c in calls[a:b]), "maintainer rearm missing")
    a = b
    b = points["old_refused_after_rearm"]["call_count"]
    require(any(c["request_id"] == "CFG001" and c["response"] ==
                {"code": "BLOCK_LOCAL_FENCE", "new_effect": False} for c in calls[a:b]), "old permit not fenced")
    require(points["rearmed"]["service_pid"] == points["fresh_effect"]["service_pid"], "service replaced after rearm")
    require(len({p["pid"] for p in case["process_receipts"]}) == 3, "two real restarts required")
    b = points["fresh_effect"]["call_count"]
    require(all(c["response"].get("new_effect", False) is not True for c in calls[b:]), "replay fresh effect")
    require(any(c["request_id"] == "CFG002" and c["response"]["code"] == "ACK_EFFECT_HISTORY"
                for c in calls[b:]), "new effect history missing")
    case = cases["FRESH_ID_BEFORE_REARM_REFUSED"]
    points = {p["label"]: p["state"] for p in case["checkpoints"]}
    before = points["fresh_quarantined_before_rearm"]
    require(before["mask"] & 1 and entry(before, "CFG002")["eligible"] is False, "fresh ID bypassed latch")
    require(points["rearmed"]["mask"] == 0, "negative case never rearmed")
    require(all(entry(case["final"], rid)["delivery_epoch"] < case["final"]["consumer_epoch"] for rid in ("CFG001", "CFG002")),
            "quarantined operation revived")
    return {"status": "PASS_EXECUTED_SCOPED", "cases": 3, "qualification": "HOLD/OPEN",
            "fresh_effect_id": "CFG002", "old_effect_count": 0, "physical_tests": "NOT_RUN"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", type=Path)
    ap.add_argument("--root", type=Path, default=HERE.parents[1])
    ap.add_argument("--negative-checks", action="store_true")
    args = ap.parse_args()
    receipt = json.loads(args.results.read_text())
    result = verify(receipt, args.root)
    if args.negative_checks:
        def case(r, name="REARM_THEN_FRESH_OPERATION"):
            return next(c for c in r["cases"] if c["id"] == name)
        def point(r, label):
            return next(p for p in case(r)["checkpoints"] if p["label"] == label)["state"]
        changes = (
            ("old_id_effect", lambda r: case(r)["final"]["effects"][0].__setitem__(0, "CFG001")),
            ("duplicate_effect", lambda r: case(r)["final"]["effects"].append(["CFG002", "synthetic-config", 0, 1, 1])),
            ("no_explicit_rearm", lambda r: point(r, "rearmed").update(mask=1)),
            ("false_service_uid", lambda r: case(r)["events"][0].update(uid=0)),
            ("missing_checkpoint", lambda r: case(r)["checkpoints"].pop(0)),
            ("missing_source", lambda r: r["source_sha256"].pop(next(iter(r["source_sha256"])))),
            ("false_global_qualification", lambda r: r["global_claims"].update(NONLEAK_END_TO_END=True)))
        rejected = []
        for name, mutate in changes:
            changed = copy.deepcopy(receipt)
            mutate(changed)
            try:
                verify(changed, args.root)
            except (ValueError, KeyError, IndexError, TypeError):
                rejected.append(name)
            else:
                raise AssertionError("false receipt accepted: " + name)
        result["negative_evidence_checks_rejected"] = rejected
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
