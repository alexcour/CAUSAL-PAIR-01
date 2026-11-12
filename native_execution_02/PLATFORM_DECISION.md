# Platform investigation — 12 November 2026

**Decision:** retain the current native SQLite composition as explicit SAMPLED_ADMISSION; keep COMMIT_DEADLINE unavailable. Select **TigerBeetle pending-transfer expiry for a separate synthetic-ledger adapter investigation**, not as a drop-in SQLite effect sink or a qualified D implementation. No external account, paid infrastructure, supplier communication or production migration is initiated.

## Documented guarantees and remaining gaps

| Candidate | Primary documentation supports | Inference for this programme |
|---|---|---|
| Current SQLite path | Commit callback can veto; approval lets COMMIT continue | Received pause witnesses already refute the tested finite-check mechanisms for D. Keep S label. |
| TigerBeetle pending transfers | At-most-once pending resolution, immutable transfer IDs, timeout-based refusal of expired posts/voids in cluster timestamp domain | Strongest concrete fit for a **ledger-expiry** experiment. Cluster event expiry is not automatically effective physical SQL-COMMIT validity in the owner boot clock. |
| Aerospike transactions | SC transaction isolation, monitor deadline, expired-command errors and a durable monitor commit-bit/finalization protocol | Worth a later source-level monitor deadline/commit-bit analysis. Consulted docs do not establish our full arbitrary-pause, external-deadline and effect-linearization contract. |
| Google Spanner | TrueTime-based transaction timestamps and external consistency | Useful ordering guarantee, but the consulted contract does not supply a caller deadline predicate atomically governing our effect. Not selected for the first adapter. |

The gap assessments and selection are our inferences from the cited contracts, not vendor statements that those products fail every possible timed use. A server timeout, ingestion timestamp, commit timestamp, result visibility and irreversible effect can denote different events; the adapter must identify each explicitly.

## Why the first adapter target is restricted

TigerBeetle uses a monotonic cluster physical time derived from replica clocks. Its event timestamps are assigned at arrival to the primary; pending timeout is relative to that cluster timestamp. Its documentation distinguishes precise expiry eligibility from best-effort removal of pending balances. An expired pending transfer cannot be posted or voided, even when pending balances have not yet been removed. These are useful observable properties for the adapter, not proof that disk/quorum commit physically happened before an owner-clock deadline under arbitrary server pauses.

No conversion from an existing boot-monotonic FCI deadline to cluster time is authorized by assumption. A proposed conversion needs a justified one-sided error bound or an explicitly different contract agreed for the experiment. A ledger transfer is the only effect in the proposed prototype; a later SQL/device action would be a second effect needing its own authorization. A successful ledger reservation cannot silently authorize a later external effect after expiry.

## Concrete adapter acceptance brief

1. Pin one official server/client release and hashes, run a local/disposable synthetic ledger only; record platform/version/source identities.
2. Map operation/permit IDs and exact content to immutable transfer IDs and user-data bindings. Retain original success versus duplicate/conflict outcomes and lookups without re-posting.
3. Test valid pending/post, late post, void-before-post, lost response/retry, conflicting ID/content, process stop/restart and history after expiry. A void can model individual revocation; it does not yet implement arbitrary FCI authority epochs.
4. Capture cluster timestamps and documented event semantics separately from wall/monotonic observations. Add adversarial server pause analysis around event timestamp assignment and state-machine commit; no new D claim from client-only delay tests.
5. Receive the raw outcomes independently, report unsupported C004 conformance obligations, and preserve UNKNOWN. Do not plug this adapter into the native SQL effect path until a separate refinement is justified.

This task completes the **native capability integration and documentary selection**. The TigerBeetle adapter is the next implementation milestone; no TigerBeetle runtime execution, physical timing qualification, independent audit or complete atomic-sink03 refinement is claimed here.

## Primary sources consulted

- [SQLite commit callback](https://www.sqlite.org/c3ref/commit_hook.html): veto versus continuation of COMMIT. Earlier native/controlled receipts remain linked in the public studies.
- [TigerBeetle Transfer reference](https://docs.tigerbeetle.com/reference/transfer/): immutable IDs, pending resolution and timeout behavior.
- [TigerBeetle Time](https://docs.tigerbeetle.com/coding/time/): primary-assigned timestamps and cluster clock domain.
- [Aerospike transaction architecture](https://aerospike.com/docs/database/learn/architecture/transactions/): monitor deadline and disk commit bit.
- [Aerospike transaction use](https://aerospike.com/docs/database/learn/transactions/): SC requirements and expiry/error handling.
- [Spanner TrueTime and external consistency](https://docs.cloud.google.com/spanner/docs/true-time-external-consistency): timestamp ordering and consistency semantics.
