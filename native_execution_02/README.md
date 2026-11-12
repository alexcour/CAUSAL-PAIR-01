# Native C execution02 — explicit temporal capability

Versioned research integration of the received execution01 composition. **SAMPLED_ADMISSION is the only supported new-effect temporal contract. COMMIT_DEADLINE is unavailable and fails closed. C004 open; M1 HOLD / SR02 BLOCKED.** This is not production qualification or a physical deadline solution.

## Observable API change

The authenticated UDS endpoint supports `capabilities_C` for C/control roles, returning a signed descriptor. Both `issue_C` and `execute_C` now require `required_capability`. Omission returns `C_CAPABILITY_REQUIRED`; an unknown or non-string value returns `C_CAPABILITY_UNKNOWN`; `COMMIT_DEADLINE` returns `C_COMMIT_DEADLINE_UNQUALIFIED`. No automatic downgrade to sampled admission or implicit default exists. Role checks still precede those capability checks.

For example, issue arguments are `{"challenge":"cccccccccccccccccccccccccccccccc","ttl":25,"required_capability":"SAMPLED_ADMISSION"}`. The issued object includes the selected capability and can be used as execute arguments. A deadline request is refused before grant/DB/native entry, including when an old result exists. `history_C` remains a separate retrieval operation and never represents a new deadline authorization. Execution and history replies state `temporal_capability=SAMPLED_ADMISSION` and `commit_deadline_qualified=false`.

Permit and RPC envelopes use version2 domains/schemas. The signed permit binds `temporal_capability`; execution policy3 binds execution.py, native_finalization.py, capability.py and owner.py. Root transition grants bind this new policy. A metadata edit cannot enable D. Existing permit/RPC clients must explicitly migrate; old version1 messages are not accepted as version2. This changes the versioned research facade, not an already deployed production service. Execution01 remains pinned historical evidence; it is not relabelled D-qualified.

## Reproduction

Python3.12 and cryptography50.0.2. Local contracts and source staging run on Windows or Linux:

```sh
python -m pip install cryptography==50.0.2
python -I -B native_execution_02/test_contracts.py
python -I -B native_execution_02/test_capabilities.py
python -O -I -B native_execution_02/test_contracts.py
python -O -I -B native_execution_02/test_capabilities.py
python -I -B native_execution_02/reproduce.py --verify-only
```

Real native captures require a disposable Linux root environment, six unused fixture UIDs62021..62026 and pidfd support. Never use a production host:

```sh
sudo python -I -B native_execution_02/reproduce.py --disposable-linux --out execution02-results
python -I -B native_execution_02/reproduce.py --read-only --out execution02-results
```

The new stage is pinned to execution01 launcher SHA256 `e52f01d4a111b5814749cd850aae8feb0f347d3e059d3135010c9362bb6f2b3c`. It stages81 files, checks all37 frozen native source hashes unchanged, and replaces only versioned execution-facade/fixture/reader files. The historical native_execution_01, activation and admission packages are not changed.

The56-cell campaign retains all seven original cases under FCI/Standard, two parent cuts and normal/-O.28 active C cells each add seven isolated capability refusals, with complete retained SQL pre/post images and signed diagnostics proving unchanged native-entry/check counters:196 refusals, including12 deadline refusals after an existing C result. The independent reader retains all old signature/SQL/native checks and adds capability evidence;410 altered witnesses must be rejected per mode. The added probes use8-second temporal-test permits instead of execution01's5 seconds, staying within the unchanged25-second maximum; this is fixture timing headroom, not a hard delay guarantee.

No late-COMMIT counterexample is hidden: supported S mode still receives four late commits. Refusal of unqualified D protects the declared API contract; it does not implement D or establish availability, global non-bypass, safe restoration or independent audit. Trusted OS/root/owner, retained authority and no clones remain assumptions. Review [PLATFORM_DECISION.md](PLATFORM_DECISION.md) for the separate platform investigation.
