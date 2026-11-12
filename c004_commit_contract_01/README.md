# C004 COMMIT contract and discriminator

**C004 remains open.** This package formalizes the distinction between a valid sampled authorization, same-database revocation ordering, and validity at effective SQLite COMMIT. A passing harness receives expected counterexamples; it does not qualify the strong deadline contract. Read [CONTRACT.md](CONTRACT.md).

The received native composition2 remains unchanged. Its pinned artifact13979046352 supplies four coherent late-COMMIT witnesses and four paired kill/rollback schedules. A read-only verifier checks artifact identity, signatures and causal bounds without running a native engine again.

A separate synthetic SQLite fixture compares the original application sample with a proposed additional COMMIT-preparation authorizer sample.24 cases cover six schedules, two gates and normal/-O. It distinguishes expiry before the recheck from an unbounded pause after the recheck. Revocation request arrival and actual revocation COMMIT are separate events in another process; an ordering table records their serialized relationship to E.

## Reproduce

Python3.12. The fixture uses only the standard library; the pinned native signature verifier requires cryptography50.0.2. Run in a disposable test directory, never against a production database. Test databases contain only synthetic values, no private keys. Native parent ZIP:3743671 bytes,SHA256 `3ffa2f423c5a929ff5daa4b8a2f42dae5d54444e86ad8d2e74e233a1a18862de`, [run43292958500](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43292958500), artifact13979046352.

```sh
python3 -m pip install cryptography==50.0.2
python3 -I -B c004_commit_contract_01/reproduce.py --verify-only
python3 -I -B c004_commit_contract_01/reproduce.py --native-parent-zip /absolute/path/native-parent.zip --out c004-results
python3 -I -B c004_commit_contract_01/reproduce.py --read-only --native-parent-zip /absolute/path/native-parent.zip --out c004-results
```

CI downloads that exact artifact through the pinned official download action. The extracted433-file inventory has SHA256 `756bb95ccdd6f82cac254527f2ea928e809df3b592b7acba8b3c2ad1f4d08205`; the verifier checks every file against this identity. CI's extracted-content verification and local verification of the complete original ZIP are explicitly distinct. The archived native source commit is `ca05c516877379d588e6af6bcc271d28ec68195e`.

Expected per environment:6 synthetic late-COMMIT counterexamples,2 preparation-time expiry refusals,8 revocation-order cells and4 killed-worker rollbacks. Distinct reader modes reject58 altered synthetic witnesses and24 altered native temporal witnesses. These are repetitions of evidence checks, not extra independent native experiments. Windows termination uses TerminateProcess; Linux uses SIGKILL. No power-loss or filesystem-crash guarantee is inferred.

Local Windows and CI Linux are distinct execution environments under the same author's control. This is not an independent external audit. The strong deadline is not established by a last clock check. A future mechanism must identify either a justified hard delay/clock-error bound or a trusted validation primitive coupled to the actual effect linearization point. M1 HOLD / SR02 BLOCKED.
