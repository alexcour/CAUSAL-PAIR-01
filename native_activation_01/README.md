# C activation and native permit01 —12 November2026

Status: implementation prepared; fresh native CI reception pending. Parent: the received public native_admission_01 sources and receiver1.1. Native engines and previous policy implementations are preserved; stage modifications and new tables are declared in a new manifest.

## Contract

Root grants activation only after the admission owner has terminated and been waited for. A distinct signed grant binds the admission receipt, business scope, retained SQL view and file identities/hashes, current policy/epoch, boot identity, policy hash and a real monotonic validity window. It is installed root-owned outside the runtime and cannot be supplied over RPC.

The controller's BEGIN IMMEDIATE transaction changes exactly C ADMISSION_ONLY→OPEN, appends a signed activation certificate and event, and retains all native B reservations. A repeat or restart of the activation component retrieves the same certificate. Four post-COMMIT B cases with no C admission must refuse activation.

The versioned issue route invokes the frozen bridge issue function to create real issuer-signed native authorization and sink-signed bridge permit for C. An additional signed versioned permit binds both to the durable activation and fresh grant. Challenge/TTL are idempotent; an expired challenge cannot silently renew. A controller-only revoke transaction fences C and advances the bridge epoch. Versioned checks and issue refuse a revoked C.

The C UID can test authorization at the new gate, under the native SQL lock and frozen bridge check. This is a **dry authorization check**, not a native execute, business COMMIT or permit consumption test. No RPC execution route is exposed. Bare bridge permits are rejected by the versioned gate; direct arbitrary calls remain outside this qualification. Revocation/expiry at the eventual real C COMMIT, normal native constructor/rearm and executing C require a separate campaign.

## Reproduce

Use a disposable Linux VM with root, Python3.12, pidfd and cryptography50.0.2. Numeric UIDs62021–62026 must be unassigned. Fixtures use real SIGKILL on child owners, Unix credentials, SQLite and freshly generated test keys. Runtime directories contain fixture private keys and must not be published. The CI publishes only its result directory.

```sh
python3 -m pip install cryptography==50.0.2
python3 -I -B native_activation_01/reproduce.py --verify-only
sudo -n "$(command -v python3)" -I -B native_activation_01/reproduce.py --disposable-linux --out "$PWD/activation-results"
python3 -I -B native_activation_01/reproduce.py --read-only --out activation-results
```

The launcher uses a pinned parent file from this repository and needs no private repository or API key. Offline re-reading requires the sources and copied result directory, not root. The original source directory remains untouched.

## Planned reception

Eight fresh native SIGKILL cases, FCI/Standard × pre/post COMMIT × normal/optimized. Four activations, eight real signed native permits (long/short), four historical refusals, four activation rollbacks,48 kernel-role denials,24 activation grant/authority holds, real short-permit expiry and refusal to renew it, revoked-permit/issue/reactivation refusals, same certificate/permit across activation-component restart, and64 actual evidence alterations rejected per reader mode. Earlier readers validate their separate earlier snapshots, not the final activation state.

Root/OS/supervisor/owner are trusted; authority retention and absence of clones remain assumptions. Time checks are monotonic and boot-bound; no cross-boot or co-restore guarantee, hostile-owner resistance, global NoBypass, independent audit, production qualification or general FCI advantage. Native C execution and normal native-service restart remain NOT_RUN. M1 HOLD / SR02 BLOCKED.
