# Native execution02 reception — explicit temporal capability, 12 November 2026

**SAMPLED_ADMISSION received in this fixture; COMMIT_DEADLINE unavailable. C004 open / M1 HOLD / SR02 BLOCKED.** This integrates the declared capability into a real versioned native research facade. It does not implement the atomic timed primitive or deploy a production service.

## Reproducible identities

- [CI43320160858 succeeded](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43320160858), executed commit `59a0127ec592a75a7f69a753b52004ee395ef48e`.
- Artifact13991196111: 4911629 bytes, 433 files; SHA256 `ab5b23314b2d13a4ded06a0162f023ed57b2048389e03ae8490c742c977bff73`. Local download verifies hash/size, ZIP CRC and path confinement. Original CI bytes remain untouched; local reception runs both readers over a separate copy.
- Staged81-file source manifest SHA256 `7b4ef4206601523bd7d29cbd4271b940862e850b2293f60411d3f38be34ee43d` matches the locally reconstructed source closure. All37 frozen native sources match the received execution01 parent. New policy3 additionally binds capability.py and owner.py alongside execution/finalization.
- All56 baseline checks and both independent offline reader modes pass. Local/CI normalized reader bytes agree exactly. Local Windows performs source staging and read-only receipt only; real native processes execute on disposable Ubuntu24.04 CI. These are not two independent native execution environments or an external audit.
- The22 retained/versioned contract tests plus15 new capability contracts pass in normal/-O. The source-gate checks prevent native, grant, DB or cache fallback on refused capability. Tests are additional to the real native campaign.

## Native results and explicit refusals

| Received quantity | Count |
|---|---:|
| Native baseline cells (FCI/Standard, parent cuts, seven cases, normal/-O) |56|
| Active C cells / historical no-C cells |28 / 28|
| C effects with durable permit consumption |12|
| Post-COMMIT lost-response recoveries |4|
| Verified typed FCI rollback receipts |4|
| Parent B SIGKILLs / C SIGKILLs |56 / 12|
| Normal native C owner startups |40|
| Explicit capability refusals with unchanged retained SQL and signed diagnostics |196|
| COMMIT_DEADLINE refusals |84|
| Missing / unknown capability refusals |56 / 56|
| Deadline refusals after an existing result was retrieved |12|
| Actually altered evidence variants rejected per reader mode |410|

The196 capability refusals are seven per active cell, not196 new native executions. Complete retained SQL pre/post images match; signed execute-entry/check/abort diagnostics remain unchanged. Deadline requests fail before grant/DB/native entry and cannot silently return an existing sampled result as deadline authorization. Independent history remains permitted retrieval and states its sampled provenance. Supported S requests still exercise native effects and the existing recovery/cut cases.

## Limits and migration

Four deliberately late S-mode releases still COMMIT after deadline. They remain received counterexamples; rejecting unsupported D is not a timing fix, a proof of useful D availability or closure of C004. Trusted OS/root/owner, retained authorities, no clones and fixture rearm assumptions remain. General non-bypass, safe co-restoration, power-loss and production qualification are not established.

Version2 permit/RPC domains and required capability argument are a deliberate client migration. There is no default to S and no configuration switch to enable D. Current unsupported-D refusal occurs before validating permit contents; it does not attest validity of a refused permit. The facade still checks caller role and request shape first. Execution01 is preserved as historical source/evidence; production routes were not migrated by publishing this package.

Temporal fixture permits are8s instead of execution01's5s to allow the extra negative probes, within the unchanged25s maximum. This is test headroom, not a hard latency bound. Both original finalizer ordering and typed-refusal behavior remain; ordinary native UNKNOWN verdicts are not relabelled. Prior failed execution01 receipts remain historical failures in their own records.

## Platform decision

[PLATFORM_DECISION.md](PLATFORM_DECISION.md) selects TigerBeetle pending expiry for a **future separate synthetic-ledger adapter**, with cluster event-time semantics and explicit gaps. No TigerBeetle runtime, provider account, physical deadline qualification or SQL effect migration occurred here. Aerospike and Spanner documentary guarantees do not by themselves supply the full D refinement; this is our scoped assessment, not a universal claim about those products.
