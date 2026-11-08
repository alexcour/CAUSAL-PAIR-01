# CAUSAL-FIBER-01 — collisions de projections causales

**Status:** toy mathematics; Python assertions locally re-executed on 2026-11-08; Lean compilation **not yet performed**. No novelty claimed for the abstract factorization theorem.

## Result

For a map p:H→O of retained observations and a verdict v:H→V, an exact reconstructor on p(H) exists iff v is constant on every fiber of p. A pair with equal p and unequal v obstructs exact reconstruction.

Synthetic histories: timely, late and stale share the observation receipt=true while the toy verdict differs; missing has receipt=false. The experiment displays two conflicting pairs. This is NOT a test of the actual FCI verifier, and the Boolean enrichment in Lean contains the verdict itself (an information-theoretic existence witness, not an implementable sensor or certificate). The Python enrichment uses a toy policy oracle.

## Reproduction

```sh
python3 causal_fiber_01/experiment.py
lean causal_fiber_01/CausalFiber01.lean
```

The second command is a requested verification step, not a completed one. No `sorry` is present in the proposed source.

## FCI and existing CAUSAL-PAIR-01

This module is complementary to `causal_pair_01` (restored receipt ambiguity) and `late_commit_02` (in-flight effect ambiguity). It does not replace or change their baselines or support any comparative advantage for FCI.

Next: bind the projection to actual verifier inputs; specify scope, freshness, authority, causal order, clock/trust assumptions, and restoration survival; check the three refusal cases; compare conventional baselines on equal trust resources. Separate abstract theorem, model checking, software execution, and physical evidence.

Do not advertise this branch as a proof of physical enforcement or as a theorem of FCI superiority.
