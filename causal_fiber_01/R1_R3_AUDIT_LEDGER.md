# R1–R3 audit ledger — scoped evidence, not native FCI qualification

Date: 2026-11-08. Status: **R1 PARTIAL / R2 FINITE_SYNTHETIC / R3 NOT_NATIVE_VERIFIED**.

This is a research audit of publicly available synthetic scenarios in this repository. It is
**not** an extraction or publication of private FCI source code, a passing native
verifier test, or a production security claim.

## R1 — observation fidelity

In `causal_pair_01`, the controller's observation includes the logical
operation and authorization, quiescence assumption, restored receipt-ledger
schema and restored receipts. The separate effect database is visible to the
experimental oracle, **not** to the basic controller.

Distinct observational layers:

1. `O_controller`: concrete serialized controller input at the decision boundary.
2. `O_receiver`: any additional trusted receiver lookup, if the policy explicitly obtains one.
3. `O_oracle`: measurement-only effect database and execution trace (never silently
   passed to either policy).
4. `O_post`: eventual observation after delayed requests have settled.

The existing restoration pair gives equal `O_controller` by construction
in a local quiescent model. This does not identify the actual inputs of any
native FCI deployment. **R1 cannot close before a version-pinned inventory of
all true admission inputs, including trusted state and async paths.**

## R2 — accessible collision and desired outcome

| History | Original effect | Receipt after restore | Basic observation | Correct recovery requirement |
| --- | --- | --- | --- | --- |
| H0 | none | empty | O | commit once, subject to valid authority |
| H1 | once | empty | O | do not commit a second time; recover prior outcome when possible |

Equal `O` and different required recovery actions forbid an exact deterministic
reconstructor on `O`. The proof is the classical fiber-constancy criterion,
instantiated in `CausalFiber01.lean` under `Recovery`. The SQLite tests
provide finite sample traces only, **not** a formal refinement between
database execution and Lean semantics.

This counterexample is about knowledge of *past effects*, not by itself proof
that an authorization credential is stale. Keep these verdicts separate.

## R3 — no effect after refusal (precise temporal property)

Let `deny(op,t_d)` mean that an admission decision refuses an operation at
logical time `t_d`. Let `commit(op,t_c)` denote the start of an irreversible
resource effect under a specific operation authority.

Proposed guarantee under a declared controlled boundary:

> A refusal is followed by no **newly admitted** commitment that relies
> exclusively on the refused authority. An effect already admitted before the
> refusal is a separate in-flight case.

The stronger formula `deny(op,t_d) => no later effect of op` is **not**
valid without assumptions on in-flight work, cancellation and recipient-side
fencing. The test must distinguish these:
- request admitted before refusal, effect observed afterward;
- request attempted after refusal;
- delayed admission from an old owner after a revocation;
- request replayed after restoration.

For each trace, measure the receiver's actual commit boundary, not only
the verifier's output. A `DENY` log line alone cannot establish R3.

## Remaining proof obligations

- `R1.1`: identify exact native code SHA, entrypoint, parsed fields, trusted
  authority and recovery state, admission barrier, recipient bypass paths.
- `R1.2`: generate canonical hashes of actual verifier observations for
  both histories, with measurement oracle excluded.
- `R2.1`: independently demonstrate both histories are reachable under
  the same failure model, and compare every field the verifier can read.
- `R2.2`: identify one trusted additional witness whose value separates
  the histories and document why it survives the modeled restore.
- `R3.1`: instrument decisions, admission calls and receiver commits using
  distinct causal event IDs.
- `R3.2`: inject delay, restoration, callback race and revoke-versus-commit
  reorderings; check post-refusal admission and in-flight effects separately.
- `R3.3`: repeat for a conventional receiver-fenced or idempotent baseline
  under identical evidence and resources.

## Exit gate

Close R1–R3 only upon an immutable evidence bundle with source SHA, environment,
trace hashes, assertions and timestamps/causal order, plus independent review.
A positive result in an abstract or SQLite model **must not** be relabeled
`FCI_NATIVE_PASS`.

The branch remains a draft; no merge or FCI release authorized.
