# C004 candidate02 — real commit hook and conditional margin

**Research experiment, not a deployable deadline primitive. C004 remains open; M1 HOLD / SR02 BLOCKED.** This extends [contract01](../c004_commit_contract_01/CONTRACT.md) without modifying or rerunning native FCI engines.

## Mechanism investigated

Register the actual SQLite C `sqlite3_commit_hook`, rather than an SQL preparation authorizer. At the callback's last sample g, return zero only if `g + margin < d`; a nonzero return asks SQLite to roll the transaction back. We test margin0 and a nominal500ms. The500ms value is an experimental parameter, not a measured or justified hard bound.

The producer owns its C SQLite connection through documented `sqlite3_open`, `sqlite3_exec`, hook and close APIs using ctypes. It never obtains or casts a CPython connection pointer. Callback code performs no SQL or connection modification. All databases and values are synthetic. The fixture uses DELETE journaling and FULL synchronization and retains effect/consumption together. The Python SQLite reader can be linked to a different SQLite version than the C library, so both versions and the C source ID are captured; simple table-file readback is the common interface.

Each gate runs valid commit, expiry before COMMIT enters the hook, pause inside the hook after a valid decision followed by release after deadline, and the same pause followed by waited process termination. Both normal/-O execute, giving16 cells per environment. A callback failure returns nonzero; unexpected exceptions or SQL results fail the harness. Windows TerminateProcess and Linux SIGKILL are process terminations, not power-loss tests.

The late-release witness gives g+margin<d<=r. Source-pinned control flow holds the COMMIT callback before returning its approval; the effective COMMIT must follow that return and the release. Durable effect readback establishes a late COMMIT under trusted OS/clock/supervisor and SQLite storage assumptions. COMMIT return alone is not used to timestamp the effect. This pause is within the final callback decision's path, not a claim to intercept a CPU instruction exactly at journal invalidation.

## Conditional bounded candidate

Let g be the measured clock sample, t its true time in the deadline's reference clock, and c the effective commit time. A proposed deployment must establish **both**:

1. One-sided clock error: `t <= g + epsilon`, with epsilon covering applicable resolution, synchronization and sampling error.
2. Hard post-sample delay: `0 <= c - t <= Delta`, including callback return, scheduling, locks, SQLite work, VFS, I/O and the chosen effective-commit definition.

Then admission only when `g + epsilon + Delta < d` is sufficient, because `c <= t + Delta <= g + epsilon + Delta < d`. Equality must refuse for an exclusive deadline. All quantities must be commensurate and arithmetic must not overflow; Python integers in the model have no fixed-width overflow. This is an algebraic conditional proof. A finite test is neither its general proof nor evidence that a real deployment satisfies its premises.

The finite integer model enumerates g0..4, d0..8, Delta0..3, epsilon0..2, signed error -epsilon..epsilon and actual delay0..8:14580 points. The separate reader verifies complete domain coverage, equations, nonvacuous bounded admissions, exclusive-deadline equality refusals, zero bounded-margin violations, and counterexamples when the delay premise is removed. Units are abstract ticks; these cases are not14580 physical transactions or timing measurements. The actual hook experiment separately exhibits violation of its nominal margin under an allowed process pause.

## Qualification gate for any future implementation

The current repository has **no qualified implementation of D**. Neither callback registration, a configuration field named Delta, a percentile, a maximum observed runtime, a benchmark PASS, nor an after-the-fact bound alarm supplies a hard delay guarantee. A monitor firing after E cannot undo an already late E. An acknowledgement can be late even if E was on time, and refusing that acknowledgement does not erase E either.

A future bounded deployment needs reviewable evidence bound to its exact executable/policy, clock/reference/deadline domain, SQLite/journal/VFS/storage configuration, scheduler/interrupt/resource assumptions, scope of locks and faults, and the complete sample-to-commit path. It also needs a justified treatment of premise failures **before an irreversible effect**. OS/process pausing permitted by the present contract defeats a finite hard bound. A watchdog relying on the same unbounded scheduling assumptions does not establish it. No such platform evidence is supplied here.

Alternatively a trusted sink could expose an operation whose specification atomically checks deadline/current epoch and applies effect+consumption at one linearization point. This is a required interface property, not a primitive implemented by the present SQLite hooks or by an abstract state transition. Moving a clock call into a VFS callback alone still requires analysis of the gap to the actual effect.

If neither route is qualified, a service requiring D must refuse that capability as unavailable; this package does not integrate that refusal into a production service or present total refusal as a usable deadline mechanism. An explicitly chosen sampled-admission S service could continue under its weaker existing contract. S cannot silently be relabelled D. No production deployment or policy migration is made in this experiment.

## Evidence and primary references

PASS means real-hook counterexamples plus the conditional model were classified as expected. It does not close C004. Separate Windows/Linux environments and readers under the same author are not an independent external audit. Original native evidence and contract01 remain historical evidence.

- [SQLite commit and rollback callbacks](https://www.sqlite.org/c3ref/commit_hook.html): nonzero converts COMMIT into rollback; zero allows it to continue; callbacks must not modify the connection.
- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html): in rollback-journal mode the effective atomic transition is distinct from the SQL-call boundary and depends on storage/OS assumptions.

These primary API semantics motivate the experiment; the reproduced late-release traces and algebra above are this programme's findings, not guarantees stated by SQLite.
