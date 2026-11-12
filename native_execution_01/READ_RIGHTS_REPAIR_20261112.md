# C result-read repair — 12 November 2026

Based on received diagnostic branch commit 9e117a1bfd279cb34c327404dbadcfa2ce8304b1. The original56-cell run43224924084 remains failed and is not reinterpreted.

The prior C admission deliberately did not grant execution or result-reading rights. Later execution permit issuance added execution authority but omitted sk_readers for UID62026, so successful native C results and post-COMMIT recovery failed READ_ROLE.

This explicit policy revision adds only the exact business-key/UID62026 read grant, atomically with durable fresh execution permit issuance. The root EXECUTE grant pins the revised policy hash. It does not authorize predecessor UIDs on new scopes, read another business key, install an arbitrary UID, or add a new RPC route. Earlier right records remain intact. The offline oracle requires this precise extra row in the permit-issuance delta and still requires exact historical result retrieval.

Three local contract tests exercise real SQLite commit/rollback, scope/preservation, and rejection outside a transaction or for another UID. They supplement the12 existing contract tests. Native CI must run the complete seven-case56-cell lot afresh.

All existing exact FCI expiry/revocation refusal obligations remain unchanged. Native HOLD_NATIVE/OUTCOME_UNKNOWN stays visible and must not be relabelled as proven nonexecution. Late COMMIT cases still document the sampled-time gap. This targeted repair may remove READ_ROLE failures while the broader qualification remains blocked. No merge or received-qualification claim until applicable evidence supports it. M1 HOLD / SR02 BLOCKED.
