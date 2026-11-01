#!/usr/bin/env python3
"""Read-only check of stored HTTP traces against the committed SQLite effects."""
import argparse
import json
from pathlib import Path
import sqlite3


def check(ok, message):
    if not ok:
        raise RuntimeError(message)


def audit(root):
    normal = json.loads((root / "normal/results.json").read_text())
    optimized = json.loads((root / "optimized/results.json").read_text())
    check(normal["environment"]["optimize"] == 0, "normal mode missing")
    check(optimized["environment"]["optimize"] == 1, "optimized mode missing")
    check(normal["cases"] == optimized["cases"], "case results or controlled traces differ across modes")
    observations, count, matrix = set(), 0, {}
    for mode, report in (("normal", normal), ("optimized", optimized)):
        check(len(report["cases"]) == 13 and report["status"] == "PASS_EXPECTED_OUTCOMES", "incomplete campaign")
        for case in report["cases"]:
            architecture, schedule = case["architecture"], case["schedule"]
            folder = root / mode / (architecture + "__" + schedule)
            stored = json.loads((folder / "trace.json").read_text())
            check(stored == case, "trace/summary mismatch")
            db = sqlite3.connect("file:" + str((folder / "receiver.sqlite").resolve()) + "?mode=ro", uri=True)
            try:
                check(db.execute("PRAGMA integrity_check").fetchone() == ("ok",), "corrupt database")
                effects = [list(r) for r in db.execute("SELECT id,k,attempt FROM effects ORDER BY id")]
                receipts = [list(r) for r in db.execute("SELECT k,effect_id FROM receipts ORDER BY k")]
                epochs = [list(r) for r in db.execute("SELECT k,epoch FROM epochs ORDER BY k")]
            finally:
                db.close()
            check(effects == case["effects"] and receipts == case["receipts"] and epochs == case["epochs"],
                  "SQLite/JSON disagreement")
            events = case["events"]
            check([e["seq"] for e in events] == list(range(1, len(events) + 1)), "trace sequence")
            commits = [e for e in events if e["event"] == "effect_committed"]
            check([[e["result"], "synthetic-operation-K", e["attempt"]] for e in commits] == effects,
                  "commits in trace disagree with effects")
            lookups = [e for e in events if e["event"] == "lookup"]
            check(len(lookups) == 1 and lookups[0]["state"] == "NOT_FOUND", "lookup premise")
            check(all(e["seq"] > lookups[0]["seq"] for e in commits), "effect preceded the lookup")
            expected = 2 if schedule != "no_old_request" and architecture == "check_before_call" else 1
            if schedule == "old_first" and architecture == "receiver_fence_only":
                expected = 2
            check(len(effects) == expected == case["final_effects"], "wrong effect count")
            arrivals = [e for e in events if e["event"] == "http_arrival"]
            expected_http = 2 + int(schedule != "no_old_request") + int(architecture == "receiver_fence_only")
            check(len(arrivals) == expected_http == case["http_arrivals"], "HTTP counts")
            old_arrivals = [e for e in arrivals if e.get("attempt") == "old"]
            if schedule == "no_old_request":
                check(not old_arrivals and case["old_response"] is None, "old request in control")
            else:
                check(len(old_arrivals) == 1 and old_arrivals[0]["seq"] < lookups[0]["seq"],
                      "old request was not pending when lookup ran")
                old_terminal = [e for e in events if e.get("attempt") == "old" and e["event"] != "http_arrival"]
                check(len(old_terminal) == 1, "missing old request outcome")
                recovery_arrival = min(e["seq"] for e in arrivals if e.get("attempt") == "recovery")
                recovery_terminals = [e for e in events if e.get("attempt") == "recovery" and e["event"] != "http_arrival"]
                if schedule == "old_first":
                    check(old_terminal[0]["seq"] < recovery_arrival, "old_first ordering violated")
                elif schedule == "recovery_first":
                    check(old_terminal[0]["seq"] > max(e["seq"] for e in recovery_terminals),
                          "recovery_first ordering violated")
                else:
                    check(schedule == "old_after_fence" and architecture == "receiver_fence_only",
                          "unexpected schedule")
                    fence = next(e for e in events if e["event"] == "fence_advanced")
                    recovery_commit = next(e for e in commits if e["attempt"] == "recovery")
                    check(fence["seq"] < old_terminal[0]["seq"] < recovery_commit["seq"],
                          "old_after_fence ordering violated")
            fenced = architecture in ("receiver_fence_only", "fence_and_reconcile")
            check(epochs == [["synthetic-operation-K", int(fenced)]], "wrong final epoch")
            check(receipts == ([["synthetic-operation-K", 1]] if architecture == "atomic_idempotency" else []),
                  "idempotency receipt not atomic with expected effect")
            if schedule != "no_old_request":
                if architecture in ("atomic_idempotency", "fence_and_reconcile"):
                    check(case["recovery_response"]["body"]["result"] == 1, "prior result not preserved")
                if schedule in ("recovery_first", "old_after_fence") and fenced:
                    check(case["old_response"] == {"http_status": 409, "body": {"state": "STALE"}},
                          "stale old request not rejected")
            observations.add(case["observation_sha256"])
            matrix.setdefault(architecture, {})[schedule] = len(effects)
            count += 1
    check(len(observations) == 1, "controllers did not receive the same base observation")
    return {"status": "PASS_ARTIFACT_AUDIT", "cases": count, "sqlite_files_read": count,
            "controlled_traces_equal_across_modes": True, "matrix": matrix,
            "scope": "same-session read-only verifier, not external validation"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parent / "results")
    args = parser.parse_args()
    result = audit(args.root)
    (args.root / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
