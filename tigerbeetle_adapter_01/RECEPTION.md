# Reception — 13 November 2026

Source tested on Ubuntu: `5d149ca8a59d1a59b69bcd7f3117b63882d8f116`.
[CI 43475510779](https://github.com/alexcour/CAUSAL-PAIR-01/actions/runs/43475510779), job132058274916: SUCCESS. Existing synthetic reproduction workflow43475510935 also succeeded.

The official0.17.9 server and Python SDK performed all eight cases in normal and optimized Python on a disposable single-replica ledger. Both Linux captures pass the SDK-free receiver;26 evidence changes are rejected per capture. Each capture posts ten units exactly once. The original posted transfer survives server process termination/restart unchanged. Timely post, expired post/void, already-voided/already-posted and conflicting-amount statuses are checked explicitly. Cluster timestamps witness expiry. No FCI native campaign was launched.

The CI artifact14062232803 was downloaded and checked locally:11459 bytes,12 ZIP entries, CRC valid, SHA256 `e9d4f01fcb88e2f87f052d3069c2f59fd0cf2368f226736f99d21a5ebdab6091` matching GitHub's digest. Both archived captures were received locally, including26 rejected changes each.

| Capture | SHA256 |
| --- | --- |
| Linux normal | `3934b98baf9cab3a2fa0712a739d64367c558fa5f52c7019ba49584cf26deea8` |
| Linux optimized | `0d2d4bdee74cc44a782eaa25c6ebdf48a2c5b41eca39be61b59aa394a4d856c4` |
| Windows normal | `64393fdbc36f11c14ba8fecb5ce0a0f9b96071bba436e47d745bb8a8589c165d` |
| Windows optimized | `6284ffb0c1bc0b593fc795e785b768dc10dba0814bcd54c104b2c3ed64276b40` |

Windows captures passed before the final disk-headroom preflight adjustment; Linux CI tests the exact source commit above. Timestamps differ between actual runs; byte identity across hosts is neither expected nor claimed.

An initial development capture explicitly posted amount0, which creates a zero-valued resolving record: the reader rejected it against the required ten-unit effect. The fixture now explicitly posts10 and verifies both balances. A subsequent startup failed with insufficient disk space. Owned disposable data files were released after stopping the server, and an upfront disk check and automatic owned-file cleanup were added. Failed development traces remain in the private working evidence; they are not successful cases.

Antigravity's mission was actually relayed and its initial ACK verified on the existing private coordination thread. Its first review covered bootstrap only. A requested follow-up report then covered the tested capture/reader and reported receiving all four captures; its reported hashes and counts match the coordinator's receipts. The agent's private report remains separate from this public scientific evidence. This is a second AI review, not an independent external audit; no general security conclusion follows.

**CLUSTER_EVENT_EXPIRY only.** Application ACK loss is simulated by discarding an already-successful reply, not by injecting a network fault. Process restart is not power loss. No authority epoch, full FCI gateway, boot-clock deadline, physical SQL COMMIT deadline, global revocation, production readiness or superiority is established. C004 remains open; M1 HOLD / SR02 BLOCKED.
