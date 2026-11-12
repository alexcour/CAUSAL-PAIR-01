# FCI finalization and exact pre-COMMIT policy refusals — revision2

**Received in native CI43292958500 at ca05c516877379d588e6af6bcc271d28ec68195e;56/56 baseline and298 mutations per mode. See RECEPTION.md.** This revision starts from PR5/dc40db6368ec234a4dfb3cf85b1212b66f0b348c. Its failed56-cell lot43289235948 remains unchanged:50 baseline passes,4 late policy UNKNOWNs and2 inconsistent late native histories. Earlier captures are not reinterpreted with these sources.

## Causes and explicit composition change

The frozen NativeBridge/SqlService stages application SQL at tx_stage, before the frozen RC3/REF3 finalizers. The temporal pause at that callback can let a later native finalizer restore a PENDING consumer while already-staged application rows still commit. Result reading correctly rejected that inconsistency. This revision defers the application SQL callback until the existing after_commit_fence hook, after all original native finalizers. It requires a native DONE entry and authenticated COMMIT_FENCE_PASS. Native denial never stages application SQL. The temporal before_commit pause now occurs after those finalizers and application/consumption staging. This change of callback placement is explicit; old temporal observations stay in their original lots.

All37 frozen native source files remain byte-identical. A new named mixin/bridge invokes the real SqlService constructor and unchanged native consumer class; it installs the supported finish hook through its versioned dispatch path. No live consumer is replaced, no native verdict or clock is patched, and no recovery flag is reset directly. STANDARD keeps its existing path. The root transition policy now binds a domain-tagged digest of both execution.py and native_finalization.py. The staged source closure has80 files.

## Exact policy refusal with durable proof

Only C_PERMIT_EXPIRED/C_REVOKED raised by the versioned admit/finish gate become a typed internal PolicyStop. That type deliberately escapes the frozen Exception handlers before the vendor COMMIT call. It does not turn a returned native UNKNOWN into a denial. The owning composition must find the native transaction still active, observe no commit callback, explicitly roll it back and verify every main-database table against the captured transaction-begin preimage through a separate read-only connection.

Only after that check does it sign a scoped rollback receipt and durably insert it in additive c_policy_aborts. The receipt binds the policy, UID, request, permit, rid, stage, exact code, boot and complete preimage. The exact RPC refusal is sent only after this receipt commits. Missing proof, changed readback, a commit observation or persistence failure leaves the call unresolved and produces no exact refusal acknowledgement. Generic native UNKNOWN replies retain their prior path and are covered by regression tests.

The independent reader keeps all existing exact refusal and native-history assertions. It additionally checks the durable signed rollback, its link to signed diagnostics, the full projected SQL preimage, the raw DONE/fence/history binding and new mutation probes. No mutation qualification starts until all56 baseline cells pass. Planned new mutation count298 per mode, not independent native cases.

## Validation and limits

21 local contract tests pass in normal and optimized Python: the prior16 plus real SQLite rollback/readback, refusal to attest committed state, allowlisted typed policy escape, deferred application staging, and no staging after a native finalizer denial. CI must exercise56 fresh cells,56 parent B kills and12 C cuts, including expiry/revocation and coherent late-COMMIT history. Synthetic tests do not establish native qualification.

The callback remains a sampled pre-COMMIT authorization point. A supervised pause after it can still produce a COMMIT after the permit deadline. This revision must preserve that limit observation and paired kill/rollback case; it does not prove a physical COMMIT deadline, C004 closure, global NoBypass, co-restore safety or production readiness. Root/OS/single owner, retained authorities, absence of live clones and fixture rearm witnesses remain trusted assumptions. M1 HOLD / SR02 BLOCKED.
