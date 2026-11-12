"""Versioned temporal contract: no configurable switch can qualify COMMIT D."""
from handoff import Refused
SAMPLED='SAMPLED_ADMISSION'
DEADLINE='COMMIT_DEADLINE'
def require_capability(value):
    if value is None:raise Refused('C_CAPABILITY_REQUIRED')
    if type(value) is not str or value not in (SAMPLED,DEADLINE):raise Refused('C_CAPABILITY_UNKNOWN')
    if value==DEADLINE:raise Refused('C_COMMIT_DEADLINE_UNQUALIFIED')
    return SAMPLED
def descriptor():
    return dict(schema='FCI-C-TEMPORAL-CAPABILITIES/1',supported_new_effect=[SAMPLED],unavailable_new_effect=[DEADLINE],
        commit_deadline_qualified=False,C004_closed=False,clock_domain='OWNER_BOOT_MONOTONIC',historical_result_is_new_authorization=False)
