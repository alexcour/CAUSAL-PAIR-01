# C004 atomic sink03

**Abstract specification and finite exploration, not a physical primitive. C004 remains open.** Read [CONTRACT.md](CONTRACT.md) and [CONFORMANCE.md](CONFORMANCE.md).

The new artifact defines new-effect versus historical-result behavior and explores complete reachable graphs for an ideal atomic timed transition and a deliberately split negative reference. Fifteen actions cover time, committed revocation, clock fault, valid/conflicting/forged requests, lost response, crash and restart. Ten named paths make the expected acceptance behavior concrete. History may return an earlier matching result after expiry without creating another effect.

The separate receiver imports no producer code and checks graph closure/reachability, transition semantics, state/receipt bindings, safety, counterexamples and changed evidence. Normal/-O reports must agree. These are finite abstract states/edges, not physical transactions, native FCI captures or a real implementation's concurrency audit. No SQLite engine is run in this package.

Python3.12, standard library only, no credentials or external dependencies:

```sh
python3 -I -B c004_atomic_sink_03/reproduce.py --out atomic-sink-results
python3 -I -B c004_atomic_sink_03/reproduce.py --read-only --out atomic-sink-results
```

Capture requires fresh output. Read-only reception replaces reports from unchanged graph/probe captures; copy archived results first to preserve originals. SOURCE_MANIFEST binds three Python files, CONTRACT.md and CONFORMANCE.md. CAPTURE_MANIFEST hashes both graphs and both probe sets. The same-author Windows/Linux runs are deterministic portability checks, not independent scientific or platform qualifications.
