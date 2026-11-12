# C004 candidate02: commit hook and bounded-margin proof obligations

**C004 remains open.** [CONTRACT.md](CONTRACT.md) gives the conditional sufficient inequality, platform qualification obligations and the exact experimental limits. This is a research fixture; it does not install a new FCI or production authorization mechanism.

The real C SQLite commit hook is sampled with margin0 and a nominal500ms, in four controlled schedules and both Python modes. Expected per environment:16 cells, four late-commit counterexamples, four expiry rollbacks, four killed-worker rollbacks and four ordinary commits. A separate reader rejects64 changed witnesses per mode. A second reader checks14580 finite arithmetic points and rejects24 changed rows per mode. The algebraic margin proof is conditional on hard delay and clock-error bounds, which these tests do not establish.

Python3.12; standard library only. Windows uses the official Python runtime's adjacent `DLLs/sqlite3.dll`; Linux requires its installed `libsqlite3` shared library. No library is downloaded by the fixture. Absence of that library fails rather than silently skipping the hook test. The C library and Python reader's SQLite versions are recorded independently. Use a disposable output directory; all DBs are synthetic and no credentials are used.

```sh
python3 -I -B c004_commit_candidate_02/reproduce.py --out candidate-results
python3 -I -B c004_commit_candidate_02/reproduce.py --read-only --out candidate-results
```

Fresh output is required for capture. To preserve archived CI bytes, copy an extracted result directory before `--read-only`; that command replaces reader reports from unchanged captures. Normal/-O report bytes must agree. Source closure hashes bind all five Python files and CONTRACT.md. No native FCI engine, parent native receipt or existing contract01 source is altered or rerun. Local and CI runs are same-author reproductions, not an external audit. No worst-case real-time, hardware or power-loss qualification is inferred.
