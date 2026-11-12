# Native C execution — received composition2, 12 November 2026

**Received:** [CI43292958500](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43292958500) at `ca05c516877379d588e6af6bcc271d28ec68195e`. All56 baseline cells pass;298 evidence mutations are rejected per reader mode. Local normal/-O readers match both archived CI outputs. See [full receipt and limits](RECEPTION.md). Global M1 HOLD / SR02 BLOCKED remain.

## Contract

Root STARTUP/REARM/EXECUTE grants bind retained authority identities and state, waited prior owner, C activation, scope, boot, time and a policy2 digest of execution.py plus native_finalization.py. The real SqlService/Standard constructors run, including lifetime locks and STARTUP. C uses an explicit adapter role extension. Supervised rearm uses synthetic fixture witnesses. Native37 source files remain unchanged; the80-file staged closure declares all composition changes.

Fresh native authorization follows the post-rearm native epoch. Permit storage atomically grants only C's exact business-key read right. FCI defers application SQL until the existing after_commit_fence hook confirms DONE and authenticated COMMIT_FENCE_PASS after all frozen finalizers. Native SQL effect, signed business result and unique permit consumption then stage in the same real effect transaction. STANDARD retains its original native transaction hooks.

Only allowlisted C expiry/revocation failures use a typed PolicyStop before the vendor COMMIT call. The owning composition rolls back and checks every main-database table against the transaction-begin preimage through a separate read-only connection. A scoped signed abort receipt commits in c_policy_aborts before an exact refusal is acknowledged. Incomplete proof leaves the call unresolved. A returned native UNKNOWN is never relabelled as nonexecution.

After SIGKILL, the supervisor waits before a new STARTUP grant. An old owner-bound execution permit cannot reauthorize a new owner. Historical retrieval verifies durable consumption, signed native/business history and the C read grant without a new effect. Missing results remain HOLD. Predecessor reservations and provenance remain retained.

## Reproduce

Disposable Linux VM only, root supervisor, Python3.12, pidfd and cryptography50.0.2. UIDs62021–62026 must be unassigned. Runtime directories contain private fixture keys and must not be published. CI uploads result captures and manifests only.

```sh
python3 -m pip install cryptography==50.0.2
python3 -I -B native_execution_01/test_contracts.py
python3 -O -I -B native_execution_01/test_contracts.py
python3 -I -B native_execution_01/reproduce.py --verify-only
sudo -n "$(command -v python3)" -I -B native_execution_01/reproduce.py --disposable-linux --out "$PWD/execution-results"
python3 -I -B native_execution_01/reproduce.py --read-only --out execution-results
```

Seven scenarios repeat each eight-cell parent group: success, before/after-C-COMMIT SIGKILL, expiry/revocation after precheck, expiry during a post-finalization pause followed by release or SIGKILL. The lot has56 parent B kills,12 C cuts,40 C normal owner startups,28 fixture rearms,12 C effects and4 durable FCI policy-abort receipts. The21 contract tests run in each Python mode. The distinct offline reader imports neither this composition nor the native engines.

## Limits and historical failures

Four supervised releases deliberately COMMIT after the wrapper deadline, with coherent native histories. The final sampled check establishes neither validity at the physical COMMIT instant nor bounded commit latency. C004 remains open. Trusted OS/root/single owner, retained authority and no clones are assumptions. One business key per fixture; no co-restore/hostile-owner guarantee, arbitrary direct-route mediation, independent audit, production qualification or general FCI superiority.

[PR5 read-repair reception](RECEPTION_READ_REPAIR_20261112.md) remains50/56 failed, including4 late UNKNOWNs and2 inconsistent native histories. [Revision1](REVISION_20261112.md), [read-right repair](READ_RIGHTS_REPAIR_20261112.md) and [finalization contract](FINALIZATION_REPAIR_20261112.md) preserve the explicit changes and earlier failures. Old captures retain their sources and hashes.
