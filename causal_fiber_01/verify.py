#!/usr/bin/env python3
"""Reproduce the audit in a fresh output directory; Python stdlib and pinned Lean."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
PIN = "Lean (version 4.29.1,"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    lean = str(args.lean.resolve())
    commands = []

    def run(name, command, cwd=HERE, env=None, expected=0):
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=120)
        text = result.stdout + result.stderr
        (out / (name + ".log")).write_text(text, encoding="utf-8")
        commands.append({"name": name, "command": command, "cwd": str(cwd),
                         "exit_code": result.returncode, "expected_exit_code": expected})
        require(result.returncode == expected, name + " failed; see " + str(out))
        return text

    version = run("lean-version", [lean, "--version"])
    require(PIN in version, "Lean version does not match toolchain pin")
    source = (HERE / "CausalFiber01.lean").read_text(encoding="utf-8")
    require(not re.search(r"\b(sorry|admit|axiom|unsafe|native_decide)\b", source),
            "unexpected proof escape or additional axiom declaration")
    run("lean-compile", [lean, "-o", str(out / "CausalFiber01.olean"), "CausalFiber01.lean"])
    lean_env = dict(os.environ, LEAN_PATH=str(out))
    axioms = run("lean-axioms", [lean, "Audit.lean"], env=lean_env)
    require("sorryAx" not in axioms, "admitted proof in transitive axiom audit")
    require(len(axioms.strip().splitlines()) == 15, "missing axiom audit output")

    negative = out / "NegativeCollision.lean"
    negative.write_text("import CausalFiber01\n"
                        "theorem invalid_collision : authorized .timely = authorized .late := by decide\n",
                        encoding="utf-8")
    rejected = run("lean-negative", [lean, str(negative)], env=lean_env, expected=1)
    require("error:" in rejected and "decide" in rejected, "negative control failed for unrelated reason")

    modes = []
    for name, flags in (("normal", []), ("optimized", ["-O"])):
        py = [sys.executable, *flags]
        run("fiber-" + name, [*py, "experiment.py"])
        run("mutations-" + name, [*py, "-m", "unittest", "-v", "test_experiment.py"])
        pair_out = out / ("pair-" + name)
        run("pair-" + name, [*py, str(REPO / "causal_pair_01" / "experiment.py"),
                             "--out", str(pair_out)])
        bridge = json.loads(run("bridge-" + name, [*py, "bridge.py", "--root", str(pair_out)]))
        modes.append(bridge)
    require(modes[0]["pairs"] == modes[1]["pairs"], "normal/optimized divergence")
    hashes = {}
    for path in sorted(HERE.glob("*")):
        if path.suffix in (".py", ".lean", ".md") or path.name == "lean-toolchain":
            hashes[str(path.relative_to(REPO)).replace("\\", "/")] = hashlib.sha256(path.read_bytes()).hexdigest()
    baseline = REPO / "causal_pair_01" / "experiment.py"
    hashes["causal_pair_01/experiment.py"] = hashlib.sha256(baseline.read_bytes()).hexdigest()
    receipt = {"status": "PASS_LOCAL_AUDIT", "source_base_commit": "09b23d3b5bd5213680973480fef8ec823c27d5e0",
               "lean_version": version.strip(), "python_version": platform.python_version(),
               "platform": platform.platform(), "python_modes": [0, 1],
               "sqlite_cases": 20, "sqlite_files_checked_read_only": 60,
               "unit_test_executions": 10, "mutants_rejected": 8,
               "lean_negative_control_rejected": True,
               "source_sha256": hashes, "commands": commands,
               "scope": "finite models and measured SQLite traces; no production FCI/refinement/physical validation"}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: receipt[k] for k in ("status", "sqlite_cases", "sqlite_files_checked_read_only",
                                             "mutants_rejected", "lean_negative_control_rejected")}, indent=2))


if __name__ == "__main__":
    main()
