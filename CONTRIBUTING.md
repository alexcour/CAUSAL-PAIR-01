# Reproduce, break, or improve the model

The repository aims to make recovery assumptions inspectable. A useful contribution can be a smaller counterexample, a missing schedule, an incorrect receiver contract, or a stronger standard baseline. No special terminology or FCI implementation is needed.

For a reproducibility issue, include:

- The commit, Python and SQLite versions, platform, and exact command.
- Whether Python ran normally or with `-O`.
- The relevant trace and final database rows for K.
- Which invariant you expected and the result you observed.

Keep the distinction between an HTTP arrival, an SQL commitment, a returned result, and a justified recovery decision. Do not silently grant a controller oracle access, knowledge of hidden scheduling, or a rollback detector.

For a new protection, specify where its evidence lives, what commits atomically with the effect, which state is allowed to be restored, and how it handles an older request that is still in flight.

Use synthetic data only. Please do not submit credentials, real operation identifiers, production databases, or private FCI code.
