# LATE-COMMIT-02: an empty lookup while an old HTTP request is still pending

This experiment gives the controller an accurate `NOT_FOUND` answer. Then an older HTTP request commits. The lookup was accurate when it ran; it did not reserve the right to execute later.

## Run a single counterexample

Python 3, standard library only. The server binds to a random **localhost** port and shuts down after each case. Use a fresh output directory.

```sh
python3 late_commit_02/experiment.py --out rerun_fence \
  --architecture receiver_fence_only --schedule old_first
```

Open `rerun_fence/receiver_fence_only__old_first/trace.json`. It records:

1. The old HTTP request arrives and waits at a harness gate before its transaction.
2. A real HTTP lookup returns `NOT_FOUND`.
3. The harness releases the old request; its effect commits at epoch 0.
4. Recovery advances the receiver epoch to 1.
5. The recovery request at epoch 1 commits a second effect.

The old request was valid when it committed. A later fence does not undo it. The recovery controller never receives the old response: only the harness collects it for measurement and scheduling.

## Controlled schedules and a progress control

The two principal pending-request schedules start with exactly the same base lookup response, operation ID, and valid authorization. Architecture-specific recovery APIs provide explicitly different guarantees; this is a comparison of receiver contracts, not a claim that the clients have equal capabilities.

```mermaid
sequenceDiagram
    participant O as Old request
    participant R as Receiver
    participant N as Recovery
    O->>R: POST execute, epoch 0
    Note over O,R: Request held before transaction
    N->>R: GET lookup
    R-->>N: NOT_FOUND
    alt old_first
        Note over O,R: Release old request; COMMIT
        N->>R: Recovery operation
    else recovery_first
        N->>R: Recovery operation
        Note over O,R: Release old request afterward
    end
```

For the separate-fence architecture, an additional `old_after_fence` schedule releases the old request after `/advance` but before the recovery execution commits. It must return `STALE`; the final effect count is one. With one atomic recovery transaction there is no separate gap between fencing and recovery effect insertion in this model.

`no_old_request` is a control verifying that each architecture can complete a fresh operation. There are thirteen cases per mode (twenty-six total). There are no sleeps to make a race likely: events determine the tested orders, and timeouts are failure backstops. This does not exhaust arbitrary interleavings, failures, or schedules involving more attempts.

## Measured matrix

Final committed effects for K; two effects mean a duplicate. The same matrix was obtained under normal and optimized Python.

| Receiver contract | Old commits before recovery | Recovery completes before old release | No old request |
|---|---:|---:|---:|
| Check before call; no target protection | 2 | 2 | 1 |
| Receiver fencing only | 2 | 1 | 1 |
| Atomic idempotency receipt and effect | 1 | 1 | 1 |
| Atomic fencing and reconciliation | 1 | 1 | 1 |

With atomic idempotency, the second request returns the same result as the first. With fencing and reconciliation, recovery returns an existing result if an effect is already present; otherwise it executes once and rejects the late epoch-0 request. The rejected old request returns HTTP 409 and `STALE`, not a success that hides a second effect.

## What is atomic here?

All effects are **synthetic SQL rows at the receiver**. Each protected operation uses one SQLite `BEGIN IMMEDIATE` transaction:

| Architecture | Transaction contract |
|---|---|
| `check_before_call` | Insert an effect; no key enforcement. The earlier lookup is a separate request. |
| `receiver_fence_only` | `/advance` increments the receiver epoch. `/execute` checks the supplied epoch and inserts an effect in one transaction. It does not reconcile earlier effects. |
| `atomic_idempotency` | Check the business-operation receipt; reuse it, or insert the effect and its receipt atomically. No epoch is needed. |
| `fence_and_reconcile` | `/recover` increments the epoch, looks for a prior effect in the authoritative receiver table, and returns that result or inserts one effect in the same transaction. Old `/execute` requests must pass the receiver epoch check. |

The receiver state is **not restored** in this chapter. No independent payment, machine command, email, or other effect outside this transaction is modelled. Moving a fence or receipt into an intermediary would require a different argument and test.

## Evidence and modest cost measurements

A campaign status of `PASS_EXPECTED_OUTCOMES` means all predicted outcomes were reproduced, including duplicates in the deliberately unsafe cases. Each case separately reports `at_most_one_effect`; campaign success does not imply that every architecture is safe.

Each case saves `receiver.sqlite` and `trace.json`; the campaign saves `results.json`. Ports and wall-clock timings are deliberately excluded from the stored traces. No latency, throughput, or storage-performance claim is made.

With an old request, the first, third and fourth architectures receive 3 HTTP requests in this model: old execution, lookup, recovery. Fencing-only receives 4 because `/advance` is separate from recovery execution. Without an old request those counts are 2 and 3. These counts describe this implementation, not a lower bound on other designs.

The read-only audit checks actual database rows, receipt and epoch tables, HTTP counts, event ordering, reused results, and stale-request rejection. The complete normal and optimized traces must match. This verifier is internal, not external review.

```sh
python3 late_commit_02/experiment.py --out rerun_http/normal
python3 -O late_commit_02/experiment.py --out rerun_http/optimized
python3 late_commit_02/audit.py --root rerun_http
```

## Make the protections fail

The mutation runner deliberately disables each essential protection and requires the experiment to fail its expected-outcome check with two actual committed effects:

| Injected defect | Exposed by |
|---|---|
| Ignore the receiver epoch | `receiver_fence_only`, `recovery_first` |
| Disable atomic deduplication | `atomic_idempotency`, `old_first` |
| Skip reconciliation of an existing effect | `fence_and_reconcile`, `old_first` |

```sh
python3 late_commit_02/mutations.py --out rerun_mutations
python3 -m unittest discover -s late_commit_02/tests -v
```

All three defects were detected in both Python modes. A mutation case exits with code 3 (`EXPECTED_OUTCOME_FAILURE`); the mutation runner exits successfully only when all six failures are detected. This helps show that the success checks are sensitive to those particular broken protections, not that all bugs have been excluded.

## What to challenge

- Add a scheduler interleaving without giving the controller access to harness gates or oracle data.
- Add loss of the authoritative receiver state, with a clearly separate effect that survives it.
- Move the final effect outside the transaction, and state how the implementation resolves unknown outcomes.
- Propose a stronger conventional baseline under explicit recovery and retention assumptions.

Report the Python and SQLite versions, exact command, trace, database rows, and expected/observed effect count. Counterexamples and corrected contracts are more useful than claims of a general exactly-once guarantee.
