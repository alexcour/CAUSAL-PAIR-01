# Candidate02 reception — 12 November 2026

**C004 open; M1 HOLD / SR02 BLOCKED.** The actual SQLite C commit hook, with and without a nominal500ms margin, does not qualify effective-COMMIT deadline validity under unbounded process pauses. [CONTRACT.md](CONTRACT.md) states the sufficient bounded-margin proof and its unproven deployment premises. This is an experiment, not a production change.

## Pins and reception

- [CI43307079935 succeeded](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43307079935), executed commit `046d60c06e8696b0f91010aed8adb550f22bbe54`.
- Six-file source-closure SHA256 `baa7380b973d0af4884f39c557fe0ef9ce2c79024a5e1db760ba4bfd0dd3c92a` matches Windows and Linux captures.
- Artifact13983942963:99774 bytes,93 files, SHA256 `b13616fd10bb0f277d723c65e81c9c3726a244a092f3aa53c00e3f31d84fb23d`. Local reception verifies ZIP size/hash, CRC and confined paths, then reruns both independent reader modes against a separate copy of the unchanged CI captures.
- Windows: Python3.12.14, C library and Python SQLite3.53.1. Ubuntu24.04: Python3.12.16, C library and Python SQLite3.45.1. C library source IDs are retained in worker reports. This receives behavior across two actual library versions, not all versions.
- SOURCE_MANIFEST, normalized RESULTS, all four normal/-O reader reports and MODEL.jsonl are byte-identical across Windows execution, original Linux archive and local CI reread. Raw physical traces and timestamps naturally differ. Modes/environments are repetitions under one author, not an external audit.

## Observations per environment

| Real hook experiment | Received |
|---|---:|
| Synthetic physical cells: two gates × four schedules × two modes |16|
| Late commits after a valid hook decision and late release |4|
| Expired-hook rollbacks, with rollback callback and empty SQL |4|
| Waited killed-worker rollbacks, empty SQL and no reply |4|
| Ordinary valid commits |4|
| Altered physical witnesses rejected per reader mode |64|

There are two late commits per gate, one per Python mode. Pausing inside the hook after a valid margin decision outlasts the nominal bound. The supervisor releases after deadline, the callback returns its approval, and SQLite completes COMMIT. Retained effect and consumption rows establish the witness; a callback is not an atomic deadline-and-effect primitive. SIGKILL/TerminateProcess observations are not power-loss tests.

| Finite integer model, abstract ticks | Received |
|---|---:|
| Complete domain points |14580|
| Margin admissions satisfying actual-delay bound |1170|
| Deadline violations among those bounded admissions |0|
| Margin counterexamples outside actual-delay bound |2214|
| Exclusive-deadline equality refusals |1575|
| Altered model rows rejected per reader mode |24|

The full model also counts5744 sampled-admission counterexamples. These are arithmetic assignments, not extra physical transactions. Its finite coverage corroborates boundary behavior; the general sufficient result comes from `c <= t+Delta <= g+epsilon+Delta < d`, explicitly conditional on actual hard delay and clock-error bounds. No physical platform bound was proved or inferred from a measured maximum. An after-the-fact alarm or refusal cannot undo an irreversible late effect.

## Decision supported

Do not promote the existing SQLite sample, preparation authorizer, commit callback or configured margin to D-qualified service. No production policy or existing native FCI engine is changed. Future D qualification requires either evidence for the complete platform-specific hard-bound premises, or a trusted primitive atomically coupling deadline authorization to the actual effect. The present ordinary Windows/Linux pause assumptions supply neither. A service explicitly offering sampled admission S must retain that name and scope.

No native FCI engines were executed, changed or counted in this study. Contract01 and its archived native witnesses retain their prior status; previous local/CI failures remain in that history. This candidate's first Windows and first Linux receptions passed; no failing candidate run is relabelled successful.
