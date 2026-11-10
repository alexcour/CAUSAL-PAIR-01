# Native admission01 — standalone public reproduction

This package preserves the exact71 deployed source files from the internally received C-admission campaign of10 November2026 and its original manifest (SHA256 `fb7f6b88d5cdfe4b903cf1ab6ac4753c8a64a9b37694461f9b200adff8e36cf8`). The default public reproduction uses the separately versioned offline receiver1.1: it corrects a mutation that could be a no-op when the two client replies were reversed. All engine, admission-policy and Participant bytes remain unchanged. See READER_V11.md. Historical private commit references are provenance, not fetch dependencies: all required source files are included here.

**Public receiver1.1 is awaiting fresh CI reception.** The first exact-source run completed reception but failed while writing the provenance file into a root-owned directory (CI42903333228). The next run exposed the no-op mutation under reversed client replies (CI42903610004). Neither overall failed run is relabelled successful. See RECEPTION.md for the final run when available.

## Run in a disposable Linux VM

The collector runs as root to provision fixtures and drops child processes to numeric UIDs62021–62026. It creates SQLite fixtures, changes ownership, uses real Unix credentials and sends real SIGKILL to its own child owner processes. Use a fresh disposable Linux VM such as a GitHub-hosted Ubuntu24.04 runner, not a production host. The launcher refuses assigned fixture UIDs and requires explicit `--disposable-linux`. It does not modify users or global system settings.

Prerequisites: Linux with pidfd support, Python3.12, root/sudo and cryptography50.0.2. No API key, private repository credential or model call is needed. Install the dependency before switching to isolated Python:

```sh
python3 -m pip install cryptography==50.0.2
python3 -I -B native_admission_01/reproduce.py --verify-only
sudo -n "$(command -v python3)" -I -B native_admission_01/reproduce.py \
  --disposable-linux --out "$PWD/public-admission-results"
```

Use a new output directory. The stage path recorded in REPRODUCTION.json is disposable and contains newly generated fixture private keys; do not publish that runtime directory. Published receipts contain public keys, signed results and SQL observations, not the fixture private-key files. The CI uploads the results directory only.

Offline re-reading of a completed output does not require root:

```sh
python3 -I -B native_admission_01/reproduce.py --read-only --out public-admission-results
```

Source-pin verification works without root. The launcher and collector require Linux even though offline readers can be used on other platforms with the pinned dependency.

## What the eight fresh cases check

FCI/Standard × before/after business COMMIT × normal/optimized owner Python. Four before-COMMIT cases should retire B and admit C as generation3 UID62026 in `ADMISSION_ONLY`; four committed-B cases should retain their historical result and refuse C admission. A signed terminal retirement certificate is not itself a handoff or execution permit: a separate root-supervisor grant is required.

Expected bounded controls: four real admission rollbacks;32 kernel-role denials;16 holds for missing grant/authority, cross-scope grant or stale view; one C per pair of client requests/repetition; four same-receipt retrievals after restarting only the admission component; eight `STALE_ALLOCATION` refusals from frozen native issue. The owner serializes requests: this is not a qualification of concurrent SQL transactions. The output key `overlapping_client_pairs` is historical terminology for pairs submitted before replies are collected.

Both offline reader modes must agree byte-for-byte within one capture run. Their60 rejected evidence alterations per mode are not60 native experiments or independent audits. Frozen crash/quiescence/retirement readers receive their earlier phase snapshots; their no-C fields are not post-admission state claims.

## Limits

No C native permit or execution, activation, normal native-service restart, production qualification, hostile-owner protection, global NoBypass guarantee, timing bound, cost advantage or general FCI superiority is established. Root, OS, supervisor and owner are trusted; absence of clones and retention of authority are assumptions. Freshness is equality with a signed retained view, not co-restore protection. FCI native MAC inspection reuses the frozen decoders; the offline reader is distinct from the implementation, not an independent external audit.

Public availability and a fresh passing run improve inspectability. They do not retroactively make the original private run independently reviewed. The raw historical private captures are not released by this package; each new run generates new fixtures, keys, process identities and receipts. Do not expect byte-identical captures between runs.

## Source lineage and rights

Source bytes were extracted from the verified internal artifact SHA256 `77f31b07016b7684f480447382008400828293cf911c884f786d791f2cceb1fd` (455877 bytes), originally executed at `b8ff1b6ba0c961346e890073661b94ef10e2e6ac`. Policy hashes, source comments and provenance references remain unchanged. Publication is authorized by the programme owner. Existing source notices are retained; this package does not invent a third-party licence or imply external endorsement.
