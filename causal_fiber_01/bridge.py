#!/usr/bin/env python3
"""Connect the fiber criterion to CAUSAL-PAIR-01 SQLite measurements.

Consumes the experiment's JSON and rechecks its SQLite rows read-only.
This is a finite trace correspondence, not a code-to-Lean refinement proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sql_rows(path, query):
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        require(db.execute("PRAGMA integrity_check").fetchone() == ("ok",), "integrity")
        return [list(row) for row in db.execute(query).fetchall()]
    finally:
        db.close()


def run(root):
    report = json.loads((root / "results.json").read_text(encoding="utf-8"))
    cases = report["cases"]
    require(len(cases) == 10, "expected five policies and two worlds")
    policies = ("blind_replay", "check_before_call", "conservative_standard",
                "fci_candidate_rule", "authoritative_witness_control")
    require({(c["policy"], c["world"]) for c in cases} ==
            {(p, w) for p in policies for w in ("never_committed", "committed")},
            "case coverage")
    pairs = []
    databases_checked = 0
    for policy in policies:
        by_world = {c["world"]: c for c in cases if c["policy"] == policy}
        empty, committed = by_world["never_committed"], by_world["committed"]
        for c in (empty, committed):
            folder = root / (policy + "__" + c["world"])
            effects = sql_rows(folder / "effects.sqlite",
                               "SELECT id,k,attempt FROM effects ORDER BY id")
            receipts = sql_rows(folder / "snapshot.sqlite",
                                "SELECT k,result FROM receipts ORDER BY k")
            sql_rows(folder / "ledger.sqlite", "SELECT k,result FROM receipts ORDER BY k")
            databases_checked += 3
            require(effects == c["effect_rows"], "effect rows differ from report")
            require(len(effects) == c["final_effects"], "effect count")
            require(receipts == c["evidence"]["receipts"] == [], "observation receipts")
            require(c["initial_effects"] == int(c["world"] == "committed"), "initial world")
            require(c["evidence"]["quiescent"] is True, "quiescence assumption")
        same = canonical(empty["evidence"]) == canonical(committed["evidence"])
        require(same == (policy != "authoritative_witness_control"), "fiber separation")
        require(empty["initial_effects"] != committed["initial_effects"], "distinct hidden states")
        if same:
            require(empty["decision"] == committed["decision"], "same-input policy")
        else:
            require(empty["evidence"]["authoritative_results"] == [] and
                    committed["evidence"]["authoritative_results"] == ["effect-1"],
                    "positive-control extra evidence")
        pairs.append({"policy": policy, "same_observation": same,
                      "final_effects": [empty["final_effects"], committed["final_effects"]],
                      "required_actions": ["EXECUTE", "RETURN_PRIOR"]})
    # Exhaust the declared one-step action space. RETURN_PRIOR cannot supply a
    # result in the empty world; BLOCK preserves safety but cannot complete it.
    actions = [{"action": a, "final_effects": [int(a == "EXECUTE"), 1 + int(a == "EXECUTE")],
                "safe_in_both": a != "EXECUTE", "empty_completed": a == "EXECUTE"}
               for a in ("EXECUTE", "RETURN_PRIOR", "BLOCK_UNCERTAIN")]
    require(not any(a["safe_in_both"] and a["empty_completed"] for a in actions),
            "shared action unexpectedly safe and live")
    return {"status": "PASS_FINITE_TRACE_BRIDGE", "cases": len(cases),
            "databases_checked_read_only": databases_checked,
            "input_sha256": hashlib.sha256((root / "results.json").read_bytes()).hexdigest(),
            "pairs": pairs, "shared_actions": actions,
            "scope": "one quiescent operation, initial effects 0/1, non-idempotent receiver",
            "not_established": ["production FCI", "physical enforcement", "formal refinement",
                                "in-flight request safety", "independent review"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.root), indent=2))
