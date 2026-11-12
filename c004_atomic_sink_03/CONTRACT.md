# C004 atomic sink03 — specification, not an implemented primitive

**C004 remains open; M1 HOLD / SR02 BLOCKED.** This study defines a sufficient abstract interface and explores a finite reference model. It does not implement, discover or qualify a physical deadline primitive, a database timed-commit facility, or a real-time platform bound. Native FCI engines and production policy are unchanged.

## Required interface and trust boundary

`commit_before(verified_permit, bound_request)` may create a new effect only at one trusted linearization point that also validates the current authority epoch, trusted deadline clock and exclusive deadline, consumes that permit and retains the exact result. `history(verified_identity, bound_request)` can retrieve that retained result without creating an effect. Authenticated request/result binding, one authoritative retained store and clock, and enforcement over every effect path are platform obligations, not properties supplied by a Python method name or lock.

A request binds rid, operation, business resource/payload digest, caller/owner, issuer/sink, boot/policy, authority epoch and exclusive deadline. Fixed bindings omitted from the finite state are held constant; they are not independently verified by the model. The finite requests A/B have different operation IDs and may each legitimately create one effect; the at-most-once property is per request/permit, not one effect across all business operations. Real signatures and IPC credentials are outside this model.

For a **new** effect E, at the same abstract transition c require: authenticated/bound request; trusted clock; current epoch equals grant epoch; `c<d`; rid not already consumed. Append effect, consumption and immutable result as one durable change. A current-epoch revocation and this change must share a serialization order. Request arrival or pending preparation is not a committed revocation. A timer firing later cannot retract E.

For an **existing** matching result, return FOUND with the original result ID and original commit time, even when the original deadline has since passed or its epoch has been revoked. This is historical retrieval, not a new authorization or new effect. The same caller scope and exact original request binding still apply. Forged credentials and conflicting bindings must not obtain cached results. A production service may impose additional history-access revocation policy; it must not turn historical retrieval into re-execution.

UNKNOWN after a lost response is not a denial or proof of absence. Repeating the same operation must retrieve a retained result if one exists. NOT_FOUND is not proof that no in-flight pending operation can later commit; a new attempt still needs the new-effect checks and shared authoritative serialization. The model contains only one outstanding prepared request, so concurrency throughput and a distributed linearizability checker are not claimed.

## Reference state and fault semantics

The reference has now0..3, authority epoch0..1, a live/offline flag, a sticky clock-health flag, at most one pending A/B, and two durable slots for effects, consumptions and results. A has epoch0/deadline2; B epoch1/deadline3. CONFLICT changes A's binding and FORGED lacks authentication. These labels represent predicates supplied by a trusted boundary, not implemented cryptography.

Fifteen actions cover time advance, one committed revocation, clock fault, preparation/query for the four request forms, commit with response or lost response, crash and restart. Time can advance offline. Clock faults block new effects and are not healed by restart. A restart retains monotonic time, current epoch and all durable records; a crash drops the pending request. Restart is in the same retained authority/clock domain. Reboot to a different clock origin, disk rollback, restoration, clones, compromised owners and physical power-loss durability require additional mechanisms and are outside the model.

ATOMIC_SPEC combines final validation and durable change in a single **assumed atomic model transition**. Crashes occur before or after that transition, never inside it. This atomic timed transition is exactly what an implementation must refine and prove; coding it as a Python state update does not provide real atomic timing or persistence. The producer is a pure finite simulator, uses no SQLite DB, performs no native effect, and measures no physical deadlines.

SPLIT_SAMPLE deliberately performs the same admission checks at preparation, then permits commit without rechecking current time, epoch or clock health. It is a negative reference exposing the gap. It is not a claim that an existing native FCI path omits all these particular checks.

The explorer visits the complete reachable finite graph with all fifteen actions from every state, including self-loops. This explores arbitrary repetitions within this finite domain; it is not a proof for unbounded time/epochs/requests or arbitrary concurrent invocations. The independent receiver checks unique states, initial state, exact action closure, reachability, transition semantics and immutable effect/consumption/result bindings, then checks safety and ten named paths. Positive and negative models must both be received. Normal/-O repetitions and Windows/Linux deterministic reproductions are not independent audits or physical experiments.

## Safety argument and progress limit

Induct over the ideal reference transitions. Initially the durable stores are empty. Only the atomic new-effect transition can append a durable slot; its guards establish trusted clock, matching epoch and c<d, and it adds all three records together. Other transitions preserve prior durable records. Existing-result responses read those immutable records and do not append. Crashes/restarts retain them. Thus deadline/epoch validity at insertion, atomic storage and at-most-once effects are inductive properties **under the stated atomic-transition and retention assumptions**. Future revocation does not falsify an earlier effect that was valid at its own commit point.

This is a conditional specification argument, not an implementation proof. No liveness deadline, fairness, bounded response time or availability under repeated faults is promised. Valid A/B commit paths make the model's safety nonvacuous. A historical reply may arrive after d without violating the condition on the original effect time.

## Relation to received SQLite results

[Contract01](../c004_commit_contract_01/CONTRACT.md) and [candidate02](../c004_commit_candidate_02/CONTRACT.md) retain their scopes and counterexamples. The SQLite commit callback can roll back on nonzero return, whereas zero allows COMMIT to continue; it is not this abstract timed atomic primitive. SQLite's rollback-journal atomicity relies on documented OS/storage assumptions and does not by itself establish a deadline check at that point. This statement follows API semantics and the earlier controlled experiments, not a new SQLite execution here.

- [SQLite commit callback semantics](https://www.sqlite.org/c3ref/commit_hook.html).
- [SQLite atomic commit and storage assumptions](https://www.sqlite.org/atomiccommit.html).

See [CONFORMANCE.md](CONFORMANCE.md) for the evidence required before any implementation could qualify this interface. C004 cannot be closed from this model PASS.
