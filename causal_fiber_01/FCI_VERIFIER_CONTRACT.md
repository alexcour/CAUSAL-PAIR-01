# CAUSAL-FIBER-01 / FCI verifier observation contract (proposed)

Date: 2026-11-08. Status: **SPECIFICATION CANDIDATE / NOT IMPLEMENTED**.
Repository branch: `research/causal-fiber-01`. This document does not certify the production FCI verifier, signature verification, hardware, or causality.

## 1. Exact decision boundary

For a proposed operation `op` (immutable payload hash, recipient, scope, operation ID),
an authority epoch `e`, and a prospective commit barrier `c`, the intended decision is:

`PERMIT` only when an authenticated, scope-matching authorization can be shown
to precede the irreversible commit barrier, to remain valid under the declared clock and
revocation policy, and when recovery cannot cause an unauthorized duplicate effect.

A `DENY` or `HOLD` result must not be represented as evidence that the historical
operation never committed. **Authorization safety** and **exactly-once recovery/liveness**
are separate verdicts, with different observations and trust requirements.

## 2. Candidate observation schema (not a claim that fields exist)

| Field | Meaning | Authority / open issue |
| --- | --- | --- |
| `op_id`, `payload_digest`, `recipient_id`, `scope` | Bind the request | Canonical encoding, collision-resistant hash, trusted request origin |
| `grant_id`, `grant_epoch`, `grant_scope`, `grant_operation_digest` | Bind the grant | Signature, key lifecycle, and issuer authorization need verification |
| `issued_at`, `not_before`, `expires_at`, `decision_time` | Time validation | Trusted clocks, drift, monotonicity and rollback assumptions unresolved |
| `precommit_witness`, `commit_barrier_id` | Causal order | Need enforcement before the irreversible receiver action; timestamps alone do not guarantee happens-before |
| `revocation_version`, `authority_epoch` | Current authority | Source of fresh revocation/epoch state and availability under partitions |
| `receiver_fence_token`, `idempotency_key`, `receiver_receipt` | Recovery protection | Atomicity, durable survival and actual recipient semantics must be independently established |
| `verification_result`, `verification_reason` | Locally derived decision | Must be recomputed by verifier; not a trusted input |

None of the above should be silently supplied from an experimenter's oracle.
A missing or unverifiable field yields `HOLD`/`DENY` by the fail-close
policy, not a guessed `PERMIT`.

## 3. Information-theoretic requirement

With real histories `H`, available verifier observations `p : H -> O` and a
specific safe authorization verdict `v : H -> Bool`, exact reconstruction
requires `p(h1)=p(h2) => v(h1)=v(h2)`.

A real-world collision is established only when BOTH histories are demonstrably
reachable and the *complete, exact verifier input* is identical. Equal log excerpts
or matching field names do not suffice.

When the observation fiber contains allowed and disallowed histories, the safe
coarse policy is to refuse permission on that fiber. Such refusal can be safe
while losing liveness; it does not recover the true verdict.

## 4. Test matrix for integration (all pending on a pinned code revision)

| Case | Evidence presented | Expected *policy* outcome | What test must prove |
| --- | --- | --- | --- |
| A0 | No grant | DENY | No irreversible action |
| A1 | Valid matching grant causally prior to barrier | PERMIT conditionally | Signature, scope, time, precommit and receiver contracts all checked |
| A2 | Expired grant | DENY | Clock boundary handling |
| A3 | Grant issued too late / arrives after barrier | DENY | Happens-before witness, not only wall-clock comparison |
| A4 | Grant for another operation/digest/recipient | DENY | No cross-operation reuse |
| A5 | Grant from an old authority epoch / revoked key | DENY | Current epoch and revocation state |
| A6 | Restored empty receipt ledger, earlier effect possible | HOLD | No blind replay; cannot conclude effect absent |
| A7 | Old request still in flight after negative lookup | HOLD or receiver-fenced resolution | Atomic fencing/receiver idempotency |
| A8 | Trusted receiver proves committed | No new effect; return recorded outcome if authorized | Signed/authoritative durable outcome |
| A9 | Missing clock, missing precommit proof, malformed or tampered witness | DENY | Fail-close under parsing and trust failures |
| A10 | Two independent requests race for same idempotency key | At most one effect | Atomic receiver contract, concurrency fault injection |

Expected outcomes are requirements, **not measured results**. A1 should not
be marked implemented without independent proof of its preconditions.

## 5. Refinement and evidence obligations

- **R1 Schema fidelity**: identify the actual functions and exact source versions that construct and parse the verifier observation; map every field or record it as unavailable.
- **R2 Reachability**: produce concrete replay traces for both sides of each claimed collision; differentiate local process state, durable DB image after crash, post-reconstruction owner state, and controller-visible input.
- **R3 Safety**: no commit occurs following DENY/HOLD, including asynchronous work, callbacks, retry paths and stale in-flight commands.
- **R4 Receiver contract**: prove or test atomic dedupe/fencing relative to the actual side effect; a lookup that returns NOT_FOUND is not sufficient.
- **R5 Trust**: authorization provenance, signed binding, clock assumptions, replay/revocation handling, rollback detection.
- **R6 Adversarial tests**: absent, expired, late, wrong scope, old epoch, restored ledger, race, signature tampering; test normal and optimized modes and crashes.
- **R7 Comparison**: same evidence and recipient capabilities for conventional fail-close, transactional outbox, fencing, idempotent receiver and any proposed FCI variant; do not claim an advantage unless a fair comparison establishes it.
- **R8 Formal bridge**: define `alpha : ConcreteState -> AbstractHistory`, `p_concrete`, and an observation-commutation condition; prove transitions preserve a stated invariant before interpreting the Lean finite model as a verifier refinement.

## 6. Explicit scope separation

Existing `causal_pair_01` measures loss of commitment receipts after restoring
a ledger; `late_commit_02` measures old in-flight operations. The toy
`causal_fiber_01` timeliness and expiry cases concern different variables.
Their conclusions must not be conflated.

The Lean file proves a classical reconstruction obstruction and finite
one-step recovery assertions. It does not independently certify SQLite,
Temporal, cryptographic authenticity, physical LED tests, or the FCI implementation.

Related work to inspect separately: private `alexcour/couret-multi-ia-lab`
PR #474 (G1 transitions and owner reconstruction), including
`SpendLedger.reserve` transaction and `SqlService.__init__` recovery writes.
Those claims require source-level verification; they are not imported as proven
facts here.

## Release gate

Do not merge or publish as a validated FCI claim until a pinned test receipt,
independent Lean compilation, real verifier observation inventory, and
a reviewed refinement/test matrix exist. Preserve `RHClaimed=false` and all
unrelated mathematical doctrine.
