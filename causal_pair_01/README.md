# CAUSAL-PAIR-01

A synthetic SQLite illustration of recovery decisions when two histories expose identical evidence to a controller.

This is an illustration of a standard information limitation. It is **not** a new impossibility theorem, a Temporal SDK integration test, or an execution of the existing FCI engine. No novelty or FCI advantage is claimed.

## Construction

- H0: no initial effect has committed.
- H1: a subprocess commits an effect, commits its receipt in a separate database, then exits with `os._exit(73)` before returning a response.
- In both histories, the receipt database is restored from the same empty, schema-valid snapshot. The effect database is not restored.

The restored ledger bytes and the serialized base observations are identical. The model assumes no old request remains in flight. The measurement oracle is separate from the evidence supplied to the four baseline rules.

## Results

Final historical effect counts for the same business operation K:

| Rule | H0 | H1 |
|---|---:|---:|
| Blind replay | 1 | 2 |
| Check restored ledger, replay if absent | 1 | 2 |
| Conventional conservative rule | 0 | 1 |
| Minimal FCI-labelled candidate rule | 0 | 1 |
| Positive control with extra authoritative evidence | 1 | 1 |

The two conservative rules deliberately use the same implementation under different labels. Their equality says nothing about a production FCI system. The witness control receives extra information under an exact lookup contract for a quiescent receiver; it is not a same-evidence comparison.

Ten cases per Python mode were run, twenty executions in total. Normal and optimized Python produced identical per-case results. A separate read-only verifier checked all sixty SQLite files and their agreement with the JSON results. That verifier was written in the same session; this is internal checking, not external validation.

## Reproduce and audit

Python 3, standard library only. No network access or credentials are required.

```sh
python3 causal_pair_01/experiment.py --out rerun_normal
python3 -O causal_pair_01/experiment.py --out rerun_optimized
python3 causal_pair_01/audit.py
```

The experiment requires a new output directory. The audit reads the delivered `normal/` and `optimized/` datasets alongside the script. Checks remain active under `python -O`.

The repository also contains the original `CAUSAL_PAIR_01_20261101.zip` archive. After extracting it, run commands from its `causal_pair_01/` directory as described in `README.txt`. Its HTML report is in French. Statements in that archived report about not yet having published the test describe the state when the archive was created.

## Limits

This model does not exercise Temporal reset, concurrency, power-loss durability, the gap between the two commits, production FCI, or performance. Blocking prevents a duplicate but leaves H0 unfinished at that point. New authoritative evidence arriving later may enable progress.

The next proposed test is a `not found` lookup followed by late commitment from an older request, with and without receiver-side exclusion. No result for that test is claimed here.

Public discussion and results: https://community.temporal.io/t/recovery-after-an-idempotency-ledger-rollback-authoritative-evidence-and-replay-safety/19893/3
