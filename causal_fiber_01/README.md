# CAUSAL-FIBER-01 — audited finite reconstruction model

Local audit on 8 November 2026: **Lean 4.29.1 compilation passed**, all fifteen
selected declarations have transitive axiom reports, and Python checks passed
in normal and optimized modes. See `RESEARCH_NOTE.md` for scope and assumptions.
The abstract factorization criterion is classical; no novelty is claimed.

## Corrections to the initial branch

The source at `09b23d3b5bd5213680973480fef8ec823c27d5e0` did not compile:
dependent equality elimination failed, and an untyped existential witness let
Lean infer the wrong predicate for `Classical.choose_spec`. Both are corrected.
The Python assertion `verdict(h) == h.receipt and extra(h)` also failed normally
because it omitted parentheses around the reconstructed verdict. All checks
now raise explicit exceptions and remain active under `python -O`.

## Reproduce

Use Python 3.11+ with its standard library and the Lean executable specified by
`lean-toolchain` (no Mathlib dependency). From the repository root:

```sh
python causal_fiber_01/verify.py --lean /path/to/lean --out /fresh/audit-directory
```

The output directory must not exist. The runner compiles the module, prints
axioms, rejects a false Lean statement, executes the toy model and four Python
mutations under both modes, reruns the ten SQLite cases in each mode, and
checks sixty resulting SQLite files read-only. It writes logs and a SHA-256
source receipt. This verification uses no HTTP server or external service.

The toy model exhausts sixteen binary enrichments of four histories; four
suffice. One bit is sufficient and zero bits fail **in that declared model**.
The enrichment still uses a policy oracle; it is not an implementable proof
source. The SQLite bridge independently concerns lost commitment evidence,
not the toy model's timeliness/freshness predicates.

`UniformlyAllowed` formalizes a conservative permit rule. The `Recovery`
namespace instantiates the collision obstruction for the two SQLite worlds
and proves the failure of any shared action to ensure both safety and
completion of the empty history in the declared one-step action model.

Local validation is not a proof of source-code refinement, production FCI,
physical enforcement, cryptographic freshness, or superiority to conventional
receiver protection. The draft PR remains subject to independent review.
