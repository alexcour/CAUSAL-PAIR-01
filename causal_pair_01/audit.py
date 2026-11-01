#!/usr/bin/env python3
"""Read-only artifact audit, deliberately independent of experiment.py helpers."""
import hashlib
import json
from pathlib import Path
import sqlite3


def check(value, message):
    if not value:
        raise RuntimeError(message)


def query(path, sql):
    con = sqlite3.connect("file:" + str(path.resolve()) + "?mode=ro", uri=True)
    try:
        check(con.execute("PRAGMA integrity_check").fetchone() == ("ok",), str(path))
        return con.execute(sql).fetchall()
    finally:
        con.close()


base = Path(__file__).resolve().parent
reports = [json.loads((base / mode / "results.json").read_text()) for mode in ("normal", "optimized")]
check(reports[0]["environment"]["optimize"] == 0, "normal mode")
check(reports[1]["environment"]["optimize"] == 1, "optimized mode")
check(reports[0]["cases"] == reports[1]["cases"], "mode mismatch")
database_count = 0
snapshots = set()
for mode, report in zip(("normal", "optimized"), reports):
    check(len(report["cases"]) == 10, "case count")
    for case in report["cases"]:
        folder = base / mode / (case["policy"] + "__" + case["world"])
        expected_initial = int(case["world"] == "committed")
        policy = case["policy"]
        if policy in ("blind_replay", "check_before_call"):
            expected_final = expected_initial + 1
        elif policy == "authoritative_witness_control":
            expected_final = 1
        else:
            check(policy in ("conservative_standard", "fci_candidate_rule"), "unknown policy")
            expected_final = expected_initial
        effects = query(folder / "effects.sqlite", "SELECT id,k,attempt FROM effects ORDER BY id")
        check(len(effects) == expected_final, "final database count disagrees with expected outcome")
        check([list(r) for r in effects] == case["effect_rows"], "JSON/database mismatch")
        check(all(r[1] == "business-operation-K" for r in effects), "operation mismatch")
        check(sum(r[2] == "initial" for r in effects) == expected_initial, "initial commitment mismatch")
        snapshot = query(folder / "snapshot.sqlite", "SELECT k,result FROM receipts")
        check(snapshot == [], "snapshot is not empty")
        ledger = query(folder / "ledger.sqlite", "SELECT k,result FROM receipts")
        check(len(ledger) == int(case["decision"] == "EXECUTE"), "unexpected final receipt count")
        snap_hash = hashlib.sha256((folder / "snapshot.sqlite").read_bytes()).hexdigest()
        check(snap_hash == case["restored_ledger_sha256"], "snapshot hash mismatch")
        snapshots.add(snap_hash)
        database_count += 3
check(len(snapshots) == 1, "snapshots differ")
audit = {"status": "PASS_ARTIFACT_AUDIT", "modes": 2, "cases": 20,
         "sqlite_files_read": database_count, "normal_optimized_case_results_equal": True,
         "single_snapshot_sha256": next(iter(snapshots)),
         "independence": "separate read-only verifier; same author, not an external review"}
(base / "audit_results.json").write_text(json.dumps(audit, indent=2) + "\n")
print(json.dumps(audit))
