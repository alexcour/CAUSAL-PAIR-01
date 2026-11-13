# TigerBeetle adapter 01 — synthetic development prototype

This fixture uses an actual pinned TigerBeetle 0.17.9 server and official Python client, one disposable replica on loopback, with two synthetic accounts. No credentials or real funds. It reports **CLUSTER_EVENT_EXPIRY**, never COMMIT_DEADLINE or FCI O6 qualification.

Eight cases: timely post, expired post, void then post, application acknowledgement discarded then exact retry, same ID with a conflicting amount, server process restart with immutable historical lookup, second post under another resolver ID, and expired void. A successful run posts exactly ten units once. Expiry is witnessed by server validation timestamps, rather than inferred solely from a host sleep. The acknowledgement case discards a successful application reply; it does not inject a transport failure. Restart is process termination and recovery of the same data file, not a power-loss experiment.

```sh
python tigerbeetle_adapter_01/bootstrap.py --runtime runner-runtime
python tigerbeetle_adapter_01/capture.py --runtime runner-runtime --out evidence/normal
python tigerbeetle_adapter_01/receive.py evidence/normal/capture.json
python -O tigerbeetle_adapter_01/capture.py --runtime runner-runtime --out evidence/optimized
python -O tigerbeetle_adapter_01/receive.py evidence/optimized/capture.json
```

Use fresh output paths. The development ledger needs about 1.14GB and is removed after the owned server stops; JSON evidence and raw logs remain. Runtime bootstrap checks official archive identities, ZIP CRC and confined paths. The SDK-free reader checks event status, fixture identity, cluster expiry, replay timestamp, restart identity and posted balances; it also rejects 26 changed evidence variants in either Python mode. It is a separate consistency reader by the same author, not an authenticated external audit.

No authority epoch or complete FCI gateway is implemented. Per-transfer cancellation does not prove global revocation. Pending-balance cleanup timing is not qualified. Cluster timestamps do not implement a caller's boot-clock deadline. The original M1 HOLD / SR02 BLOCKED and C004 remain.

Primary references: [Python client](https://docs.tigerbeetle.com/coding/clients/python/), [create_transfers results](https://docs.tigerbeetle.com/reference/requests/create_transfers/), [installation](https://docs.tigerbeetle.com/operating/installing/). Runtime download sizes and hashes are recorded in bootstrap.py.
