# C004 — sampled permission, serialized revocation and effective COMMIT

Status: contract and discriminating test. No physical deadline qualification or C004 closure is claimed.

## Definitions

P identifies one permit, operation, business key, issuer/sink bindings, owner, boot, policy and authority epoch. Its exclusive deadline d uses the same trusted monotonic clock as the service. E denotes durable effect plus its result and permit-consumption row in one retained SQLite transaction. g is the final sampled gate decision. c is the actual SQLite atomic-commit linearization point. u is the time when COMMIT returns to the caller. R is a committed revocation transition in the same authority database, not the arrival of a revocation request.

The existing native composition2 receives the authenticated P bindings, single consumption, native DONE/PASS consistency and sampled condition g<d in its stated fixture. That does not supply the stronger condition c<d.

| Property | Required statement | What the test can establish |
|---|---|---|
| S: sampled authorization | E implies valid bindings/current epoch and g<d | A sampled admission property; no COMMIT-time claim |
| A: atomic effect/consumption | Effect, result and consumption commit together or none commit | Retained SQL readback after success/kill, within the fixture |
| R: serialized revocation | Once R commits, a later effect using the old epoch is blocked | Same-database transaction order; request arrival is insufficient |
| D: effective deadline | E implies c<d | Refuted for a tested gate if a controlled release r>=d must occur before its successful COMMIT |

Scope is one SQLite authority database in DELETE journal mode with FULL synchronization. SQL atomicity and durability rely on SQLite's documented OS/storage assumptions. Physical actuator effects, hostile owners, clones, co-restoration and cross-host clock agreement are outside this contract.

## Discriminating schedules

The new fixture compares APPLICATION_SAMPLE with COMMIT_PREPARE_AUTHORIZER. The latter performs another deadline sample in the SQLite authorizer when the COMMIT statement is prepared; statement caching is disabled. It is explicitly a preparation-time callback, not a commit hook or atomic clock-and-commit primitive. The fixture does not run the FCI or Standard native engines and does not add an FCI security result.

Each gate runs six schedules in normal and optimized Python: valid commit; expiry before SQL COMMIT preparation; pause immediately after the last valid sample followed by late release; the same pause followed by process termination; revocation committed before the effect transaction; and revocation requested while the effect holds BEGIN IMMEDIATE. The controller runs in a distinct process. Its request marker and its completed SQL transition are recorded separately. A retained ordering table distinguishes E-before-R from R-before-E.

The preparation recheck must reject expiry that has already occurred before its sample. Both gates must still expose a late-COMMIT counterexample when paused after their own final successful sample. Kill schedules must leave neither staged effect nor consumption. A prior committed revocation must block the old epoch. A revocation request waiting behind the effect's write transaction can commit after E, which does not violate the defined R-order property. Request/observation/release clock samples can tie at finite clock resolution: causal order comes from the supervisor's file handshake, and strict E-before-R order comes from distinct committed SQL sequence entries. Nanosecond units do not imply nanosecond resolution.

## Causal witness and limits of measurement

For a late release, the observed trace must establish g<d<=r and a successful COMMIT after the instrumented pause. The code location requires COMMIT execution to follow release, so c>=r>=d under the trusted supervisor/clock and program-order assumptions. Durable post-COMMIT SQL readback supplies E. An exact timestamp for c is unnecessary to refute c<d. COMMIT-return time u alone would only be an upper bound and is not used as a lower bound on c.

The four archived native late releases and four paired kill schedules retain their original source commit ca05c516877379d588e6af6bcc271d28ec68195e and complete artifact hash. Their separate witness verifier checks signatures, request/result/consumption bindings, program-point markers and causal bounds. It never calls an engine, repairs state or rewrites the original receiver's result.

## Restricted last-sample argument

For mechanisms that make their final finite authorization observation before c and then permit an unbounded scheduling pause without atomically invalidating the pending commit, choose a valid sample g<d and pause past d before allowing c. The accepted transaction violates D. Another finite sample only relocates that gap. This is a statement about that mechanism class and its pause assumptions, not an impossibility theorem about every database or timed actuator.

A possible sufficient assumption would be a proven hard bound c-g<=Delta together with an accurate common-clock error allowance epsilon and admission rule g+Delta+epsilon<d. No measured maximum from these fixtures establishes such a bound. A future proposal must identify and justify either that bound or a trusted validation primitive that couples the deadline decision to the actual effect linearization point. Until then D and C004 remain unqualified.

## Evidence routing

A harness PASS means that the expected outcomes and counterexamples were correctly classified. It does not mean D passes. Output must retain physical_COMMIT_deadline_contract=COUNTEREXAMPLES_RECEIVED, C004_closed=false, M1=HOLD and SR02=BLOCKED. Normal/-O are repetitions. Local Windows and CI Linux are distinct execution environments under the same author's control, not an independent external audit.

## Primary references

- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html), especially single-file rollback-journal invalidation and storage assumptions: the SQL call boundary is distinct from the effective commit point.
- [SQLite authorizer](https://www.sqlite.org/c3ref/set_authorizer.html): authorization is invoked while compiling statements and may deny their preparation.
- [SQLite transaction semantics](https://www.sqlite.org/lang_transaction.html): write transactions serialize; BEGIN IMMEDIATE can encounter an existing writer.
- [Python3.12 sqlite3](https://docs.python.org/3.12/library/sqlite3.html): authorizer binding and statement-cache configuration used by the fixture.
