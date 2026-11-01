#!/usr/bin/env python3
"""Three deliberately broken protections must be detected in BOTH Python modes."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), "use a fresh output directory")
    args.out.mkdir(parents=True)
    mutations = (("receiver_fence_only", "recovery_first", "disable_fence"),
                 ("atomic_idempotency", "old_first", "disable_dedup"),
                 ("fence_and_reconcile", "old_first", "ignore_prior_commit"))
    results = []
    for optimize in (False, True):
        for architecture, schedule, fault in mutations:
            folder = args.out / (("optimized__" if optimize else "normal__") + fault)
            command = [sys.executable] + (["-O"] if optimize else [])
            command += [str(Path(__file__).with_name("experiment.py")), "--out", str(folder),
                        "--architecture", architecture, "--schedule", schedule, "--fault", fault]
            run = subprocess.run(command, capture_output=True, text=True, timeout=30)
            require(run.returncode == 3, "mutation was not caught: " + fault + run.stderr)
            report = json.loads((folder / "results.json").read_text())
            case = report["cases"][0]
            require(report["status"] == "EXPECTED_OUTCOME_FAILURE" and case["final_effects"] == 2
                    and case["expected_effects"] == 1, "unexpected mutation failure")
            results.append({"fault": fault, "optimize": int(optimize), "exit_code": run.returncode,
                            "final_effects": case["final_effects"], "detected": True})
    summary = {"status": "PASS_MUTATION_CHECKS", "checks": results}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
