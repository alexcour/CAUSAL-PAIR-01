# Atomic sink03 reception — 12 November 2026

**Abstract specification received; no physical primitive implemented or qualified. C004 open, M1 HOLD / SR02 BLOCKED.** [CONTRACT.md](CONTRACT.md) defines new-effect versus historical-result behavior and the explicit atomic-transition assumptions. [CONFORMANCE.md](CONFORMANCE.md) lists implementation evidence still missing.

## Evidence identity

- [CI43310332533 succeeded](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43310332533), executed commit `d7e5d42a69e8859accc7a9a8ae6e645327a07255`.
- Five-file source closure SHA256 `bac4577982dad64670f5a5b42bbff5cbba6f90a3427857482ce119d8c5ff6895` binds the three Python files and both contract/conformance documents.
- Artifact13985447394:64461 bytes,11 files, SHA256 `aafb1f0edaab90d26a4e6c94fcedc60833faa09b131129b483b74044b6e9e9c2`. Local reception verified ZIP size/hash, CRC and confined paths, then ran both receiver modes against a separate copy of unchanged CI captures.
- Windows Python3.12.14 and Ubuntu24.04 Python3.12.16 produce byte-identical graph/probe files, capture/source manifests, normal/-O receiver reports and normalized RESULTS. The local CI reread matches all those bytes too. CI execution/environment receipts are additional CI-only files.
- Deterministic same-author portability and receiver checks are not independent external review, physical timing experiments or implementation refinement proof. No SQLite or native FCI engine ran in this study.

## Complete reachable finite graphs

| Quantity | ATOMIC_SPEC | SPLIT_SAMPLE |
|---|---:|---:|
| Reachable abstract states |218|560|
| Transition edges, fifteen actions per state |3270|8400|
| New-effect edges |20|120|
| Edges creating a late effect |0|44|
| Edges creating an effect under a stale epoch |0|16|
| Edges creating an effect under untrusted clock |0|60|
| Cached-result reply edges |232|768|
| Lost-reply effect edges |10|60|
| Named fault/retry paths |10|10|

These are graph states/edges, not physical transactions or independent experiments. Edges include distinct reply/lost-reply forms and multiple state contexts; violation categories overlap and must not be added as disjoint cases. A complete finite graph covers arbitrary action repetition within its stated domain, including cycles; it does not cover unbounded clocks/epochs/requests or arbitrary concurrency.

Each receiver mode rejects32 actually altered evidence variants across the two graphs and twenty path checks. Receiver verification includes exact initial state, unique nodes/edges, all-action closure, reachability, contract transitions, retained effect/consumption/result binding and immutability. Both safety and a deliberately faulty comparison are required; it is not a trivial no-effect success.

## Consequence for recovery

The named lost-response path first commits with UNKNOWN, crashes, advances beyond A's deadline, restarts, commits an epoch revocation, then retries A. The retry returns the exact original retained result without appending an effect. Other paths distinguish pending-work loss, rejection at exclusive-deadline equality, stale epoch, sticky clock fault, valid next-epoch commit, and denial of conflicting/forged cache requests. NOT_FOUND is not promoted to proof that no pending effect can later occur.

The ideal reference has zero violations because final time/epoch/clock validation and effect+consumption+result are one assumed atomic transition. An induction argument states that assumption explicitly. It remains the missing implementation property, not a result created by running Python. The split model supplies concrete finite counterexample paths when final validation is separated from effect.

## Implementation disposition

No platform candidate or physical adapter is qualified by this reception. Existing received SQLite sample/authorizer/commit-hook and nominal-margin studies keep their limits. Future work requires a specific platform/supplier whose complete deadline coupling or hard-bound evidence can be reviewed, then an adapter/refinement and real fault captures. No production policy, native FCI engines, clocks or sharing policy were changed. No failing run is relabelled successful; both first receptions of this specification passed, while earlier study failures remain in their existing histories.
