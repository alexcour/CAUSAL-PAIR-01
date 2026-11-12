# C native execution01 — 12 November 2026

**Qualification pending.** Separate research composition after received C activation. No received result claimed until native CI and independent offline reception succeed.

The launcher pins the public activation parent, which pins the standalone admission parent and37 frozen native sources. It adds two empty tables before any B call. Seven fresh scenarios repeat each of the eight parent cells: the original success, before/after-C-COMMIT SIGKILL, expiry after precheck and revocation after precheck, plus expiry during a pause after final transaction sampling followed by release or SIGKILL. Fifty-six parent B SIGKILLs and twelve additional C cuts are planned. The temporal release case deliberately documents a possible COMMIT after deadline; it does not satisfy a commit-before-expiry contract.

Root signs explicit STARTUP, REARM and EXECUTE grants binding retained state/authority identity, waited previous owner, C activation, scope, policy, boot and time. The normal NativeBridge constructor invokes the real SqlService/Standard constructor, including lifetime lock and STARTUP. The C role is explicitly installed by the adapter; Standard keeps its installed configuration and authenticates the actual signed C UID through the versioned facade. The inherited safe_rearm helper uses synthetic fixture witnesses, not independent repair evidence. No direct recovery/poison/epoch resets are introduced.

After rearm, a fresh issuer authorization binds the new native epoch. A distinct consumable wrapper binds the fresh root grant, owner PID, activation and request. The real native effect transaction stages the business result and inserts the unique permit consumption. Both roll back or commit together. The wrapper and current control are checked after SQL staging; this is the final sampled authorization point, **not a bound on elapsed time from sampling through actual COMMIT**.

On restart, a fresh root STARTUP grant requires the killed previous owner to have been waited for. The old execution grant remains bound to the previous PID and cannot reauthorize execution. Historical result retrieval verifies the signed native/business history and durable consumption without producing a new effect. An absent result remains HOLD, not permission to retry. B reservations are retained; native rearm may explicitly quarantine a native phase and advance epochs.

## Run

Disposable Linux VM only, root supervisor, Python3.12, pidfd, cryptography50.0.2; numeric UIDs62021–62026 must be unassigned. No production systems. Fixture runtime directories contain private test keys and must never be published. CI uploads only result captures and manifests.

```sh
python3 -m pip install cryptography==50.0.2
python3 -I -B native_execution_01/reproduce.py --verify-only
sudo -n "$(command -v python3)" -I -B native_execution_01/reproduce.py --disposable-linux --out "$PWD/execution-results"
python3 -I -B native_execution_01/reproduce.py --read-only --out execution-results
```

Offline reader imports the prior evidence readers and signature primitives, never the execution/native implementations. It verifies the earlier admission evidence in seven distinct eight-cell groups, then signed grants/requests/results, kernel peers, isolated negative probes, snapshots, COMMIT cuts, effect/consumption equality, preservation of predecessor rights and evidence mutations. Both normal/-O readers run even if one fails. A per-cell DIAGNOSTIC_ONLY report is emitted before any qualification claim; baseline failures still fail the job. Normal/-O are repetitions, not independent external audits.

The 12 local contract tests run in each Python mode before native collection. They exercise actual wrapper checks and the facade dispatch method with an SQLite fixture, not a real native engine or UDS owner. Native qualification remains a separate CI obligation.

## Preserved failure and targeted correction

Run [43124669096](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43124669096), commit ff42f6c47c854586b603205c104108312b6ba75c, remains FAILURE. Artifact 13903056383 (SHA-256 4a106118dccb810d843891914883d4f718bd05adc49edd406c8805fdb6eee0d8) contains SIGNATURE refusals in all 20 activated-C cells; receive.py required SIGNATURE_INVALID. The frozen handoff verifier already wraps InvalidSignature in Refused('SIGNATURE'). The new facade now maps exactly that code to SIGNATURE_INVALID; every other Refused propagates unchanged. No original evidence is rewritten.

The same artifact also contains four FCI HOLD_NATIVE/OUTCOME_UNKNOWN responses for expiry/revocation after precheck. The exact refusal requirements C_PERMIT_EXPIRED/C_REVOKED remain enforced. Diagnostic instrumentation records the first wrapper failure stage and propagates its original exception; it never converts an unknown native outcome into a proven refusal. No new qualification is claimed in advance of CI.

## Limits

Trusted OS/root/single owner, retained authority and no live clones remain assumptions. New versioned adapter and root transition policy; no general mediation of arbitrary direct native calls, no hostile-owner protection, no co-restore safety or industrial time bound. One business key per fixture. Normal constructors and explicit native C execution do not establish production readiness, global NoBypass or general superiority. M1 HOLD / SR02 BLOCKED.
