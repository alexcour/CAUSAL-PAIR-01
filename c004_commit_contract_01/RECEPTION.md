# C004 — received contract and counterexamples, 12 November 2026

**C004 remains open; M1 HOLD / SR02 BLOCKED.** Harness success means expected counterexamples were received, not that effective-COMMIT deadline validity was established. Read [CONTRACT.md](CONTRACT.md) for definitions, assumptions and the restricted last-sample argument.

## Executed identities

- [Successful CI43304723750](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43304723750), executed source `6914d73ca6b5745a3f15002e6f87e1861551aa1e`; Ubuntu24.04, Python3.12.16. Separate local Windows execution used Python3.12.14.
- Five-file source manifest SHA256 `31ef24272cb33b76e1df4b5944ff5bb43cd177582c21a67f2d7c56450f36eea6` is identical in both environments. No native engine was changed or rerun.
- CI artifact13983446644:63750 bytes,140 files; SHA256 `80818d0ece5259faf08ebb6211534d23f9a4c8eb48b77d9b15f7b9a2d3a4c593`. Local reception verified full ZIP size/hash, CRC and confined paths, then reran both evidence readers against its unchanged captures in a separate output copy.
- Native parent artifact13979046352 from [CI43292958500](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43292958500):3743671 bytes,433 files, SHA256 `3ffa2f423c5a929ff5daa4b8a2f42dae5d54444e86ad8d2e74e233a1a18862de`. Local verification uses exact ZIP identity; CI verifies its complete extracted content inventory `756bb95ccdd6f82cac254527f2ea928e809df3b592b7acba8b3c2ad1f4d08205`. The two methods are explicitly distinguished in reports.

## Results and interpretation

| Per execution environment | Received |
|---|---:|
| Synthetic cells: six schedules × two gates × normal/-O |24|
| Late-COMMIT counterexamples |6|
| Expiry refusals at preparation recheck |2|
| Revocation-order cells |8|
| Killed-worker rollbacks |4|
| Altered synthetic witnesses rejected per reader mode |58|

The separate pinned native witness reader receives four archived late-COMMIT witnesses and four paired kill/rollbacks, rejecting24 altered witnesses per mode. These are reread old captures, not eight new native executions. Neither synthetic fixture supplies native FCI or IPC-role security qualification.

Normal/-O reader outputs are byte-identical within each environment. Windows and Linux normalized aggregate JSON results agree, and local rereading of the CI captures agrees structurally with the archived CI reports; native input-verification labels differ as described above. Cross-platform newline bytes are not claimed identical. Distinct environments and separately implemented readers remain under the same author's control, not an independent external audit.

The additional authorizer sample rejects an expiry already present before COMMIT preparation. A controlled pause after its own last successful sample still permits a late COMMIT. Revocation committed before the transaction blocks the old epoch; a request arriving while that transaction holds the write lock can commit after its effect. The contract distinguishes these events rather than treating request arrival as committed revocation.

## Preserved failures

The first local full reception failed because the reader required strictly increasing clock samples where Windows finite-resolution samples tied. Its original five source files and failed captures are retained in the private archive. The correction permits tied sample readings while retaining the explicit causal file handshake and strict durable SQL E-before-R order; nanosecond units do not imply nanosecond resolution.

[First CI43303870144](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43303870144) failed its parent-inventory check after collecting24 cells: the download action extracted the pinned archive into `native-parent/native-execution-43292958500`, while the receiver was passed its parent directory. Artifact13983131081 remains failed:60150 bytes, SHA256 `d3e71f2edfdc963f55902eac714a36d8b6f5353ae9d6e83f306db1e8f9c3632b`. Only the workflow input path changed for the successful run; no identity check was relaxed. Earlier native campaign failures remain in their own reception histories.

## Next mechanism acceptance criterion

A new proposal must justify a hard bound from last sample to effective commit, including clock error, or identify a trusted primitive coupling temporal authorization to effect linearization. The current finite-sample mechanisms do not establish either. Measured maxima alone do not prove a hard bound. Production qualification, general non-bypass, safe co-restoration and C004 closure remain unclaimed.
