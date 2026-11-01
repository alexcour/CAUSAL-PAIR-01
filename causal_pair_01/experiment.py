#!/usr/bin/env python3
"""CAUSAL-PAIR-01: a local SQLite model, not a Temporal/FCI integration."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys

K = "business-operation-K"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def connect(path):
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA synchronous=FULL")
    return db


def initialize(folder):
    folder.mkdir(parents=True, exist_ok=False)
    db = connect(folder / "ledger.sqlite")
    db.execute("CREATE TABLE receipts(k TEXT PRIMARY KEY, result TEXT NOT NULL)")
    db.commit()
    db.close()
    shutil.copyfile(folder / "ledger.sqlite", folder / "snapshot.sqlite")
    db = connect(folder / "effects.sqlite")
    # No uniqueness on k: this models a non-idempotent receiver.
    db.execute("CREATE TABLE effects(id INTEGER PRIMARY KEY, k TEXT NOT NULL, attempt TEXT NOT NULL)")
    db.commit()
    db.close()


def effect_and_receipt(folder, attempt):
    db = connect(folder / "effects.sqlite")
    cursor = db.execute("INSERT INTO effects(k, attempt) VALUES (?, ?)", (K, attempt))
    result = "effect-" + str(cursor.lastrowid)
    db.commit()
    db.close()
    db = connect(folder / "ledger.sqlite")
    db.execute("INSERT OR REPLACE INTO receipts VALUES (?, ?)", (K, result))
    db.commit()
    db.close()
    return result


def rows(path, sql):
    db = sqlite3.connect("file:" + str(path.resolve()) + "?mode=ro", uri=True)
    try:
        require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", str(path))
        return db.execute(sql).fetchall()
    finally:
        db.close()


def observation(ledger):
    # Explicit controller interface: no clock, trace, effect DB, path, or oracle.
    receipts = rows(ledger, "SELECT k, result FROM receipts ORDER BY k")
    return {"operation": K, "authorization": "valid", "quiescent": True,
            "ledger_schema_valid": True, "receipts": receipts}


def decide(policy, evidence):
    if policy == "blind_replay":
        return "EXECUTE"
    if policy == "check_before_call":
        return "RETURN_PRIOR" if evidence["receipts"] else "EXECUTE"
    if policy in ("conservative_standard", "fci_candidate_rule"):
        return "RETURN_PRIOR" if evidence["receipts"] else "BLOCK_UNCERTAIN"
    if policy == "authoritative_witness_control":
        return "RETURN_PRIOR" if evidence["authoritative_results"] else "EXECUTE"
    raise ValueError(policy)


def run_case(root, policy, committed):
    world = "committed" if committed else "never_committed"
    folder = root / (policy + "__" + world)
    initialize(folder)
    trace = ["empty ledger snapshot created"]
    if committed:
        command = [sys.executable]
        if sys.flags.optimize:
            command.append("-O")
        command += [str(Path(__file__).resolve()), "--worker", str(folder)]
        worker = subprocess.run(command, capture_output=True, text=True, timeout=20)
        require(worker.returncode == 73, "worker did not stop at the declared cut")
        require(worker.stdout == "", "worker unexpectedly returned a result")
        require(len(rows(folder / "ledger.sqlite", "SELECT * FROM receipts")) == 1,
                "receipt not committed before cut")
        trace += ["effect COMMIT", "receipt COMMIT", "worker os._exit(73) before response"]
    pre = len(rows(folder / "effects.sqlite", "SELECT * FROM effects"))
    require(pre == int(committed), "incorrect initial effect count")
    # All SQLite connections are closed; DELETE mode leaves no live WAL to omit.
    require(not list(folder.glob("*-wal")), "unexpected WAL")
    shutil.copyfile(folder / "snapshot.sqlite", folder / "ledger.sqlite")
    require(digest(folder / "ledger.sqlite") == digest(folder / "snapshot.sqlite"),
            "restoration not byte-exact")
    trace.append("ledger restored byte-for-byte; effect database untouched")
    evidence = observation(folder / "ledger.sqlite")
    require(not evidence["receipts"], "restored evidence is not empty")
    evidence_hash = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
    ledger_hash = digest(folder / "ledger.sqlite")
    if policy == "authoritative_witness_control":
        # Deliberately grants EXTRA information, not a fair same-evidence baseline.
        # Trusted exact lookup is valid here only because the model is quiescent.
        evidence["authoritative_results"] = ["effect-" + str(r[0]) for r in rows(
            folder / "effects.sqlite", "SELECT id FROM effects ORDER BY id")]
    decision = decide(policy, evidence)
    result = None
    if decision == "EXECUTE":
        result = effect_and_receipt(folder, "recovery")
    elif decision == "RETURN_PRIOR":
        result = (evidence.get("authoritative_results") or [r[1] for r in evidence["receipts"]])[0]
    final = rows(folder / "effects.sqlite", "SELECT id, k, attempt FROM effects ORDER BY id")
    require(len(final) == pre + int(decision == "EXECUTE"), "unexpected final effect count")
    return {"policy": policy, "world": world, "base_observation_sha256": evidence_hash,
            "restored_ledger_sha256": ledger_hash, "evidence": evidence,
            "initial_effects": pre, "decision": decision, "final_effects": len(final),
            "duplicates": max(0, len(final) - 1), "returned_result": result,
            "prior_result_reconstructed": committed and result == "effect-1",
            "no_effect_history_completed": (not committed) and len(final) == 1,
            "effect_rows": final, "trace": trace}


def experiment(destination):
    require(not destination.exists(), "use a fresh output directory")
    destination.mkdir(parents=True)
    policies = ["blind_replay", "check_before_call", "conservative_standard",
                "fci_candidate_rule", "authoritative_witness_control"]
    cases = [run_case(destination, p, c) for p in policies for c in (False, True)]
    require(len({c["base_observation_sha256"] for c in cases}) == 1, "base observations differ")
    require(len({c["restored_ledger_sha256"] for c in cases}) == 1, "restored database bytes differ")
    for p in policies:
        empty, prior = [c for c in cases if c["policy"] == p]
        if p in ("blind_replay", "check_before_call"):
            require(empty["final_effects"] == 1 and prior["final_effects"] == 2, "replay control")
        elif p == "authoritative_witness_control":
            require(empty["final_effects"] == prior["final_effects"] == 1, "witness control")
            require(prior["prior_result_reconstructed"], "witness failed reconstruction")
            require(empty["evidence"] != prior["evidence"], "witness adds no information")
        else:
            require(empty["final_effects"] == 0 and prior["final_effects"] == 1, "block control")
    report = {"experiment": "CAUSAL-PAIR-01", "status": "PASS_LOCAL_MODEL",
              "cases": cases, "scope": "stdlib SQLite model; no Temporal SDK or production FCI",
              "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                              "optimize": sys.flags.optimize},
              "claim": "No tested same-evidence policy achieves both duplicate avoidance and completion of the empty history."}
    (destination / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "cases": len(cases), "output": str(destination)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.worker:
        effect_and_receipt(args.worker, "initial")
        os._exit(73)
    require(args.out is not None, "--out is required")
    experiment(args.out)
