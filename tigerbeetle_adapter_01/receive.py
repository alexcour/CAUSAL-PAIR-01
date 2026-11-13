"""SDK-free evidence consistency reader. Not an authenticated independent audit."""
import argparse, copy, hashlib, json
from pathlib import Path

def need(ok, message):
    if not ok: raise ValueError(message)

EXPECTED = {
    'pending_live': 'CREATED', 'post_live': 'CREATED',
    'application_ack_discard_retry': 'EXISTS',
    'id_amount_conflict': 'EXISTS_WITH_DIFFERENT_AMOUNT',
    'second_post': 'PENDING_TRANSFER_ALREADY_POSTED',
    'pending_void': 'CREATED', 'void_live': 'CREATED',
    'post_voided': 'PENDING_TRANSFER_ALREADY_VOIDED',
    'pending_expiring': 'CREATED', 'post_expired': 'PENDING_TRANSFER_EXPIRED',
    'void_expired': 'PENDING_TRANSFER_EXPIRED',
}

def check(r):
    need(r['schema'] == 1 and r['capability'] == 'CLUSTER_EVENT_EXPIRY' and r['commit_deadline'] is False, 'scope')
    need(r['runtime']['version'] == '0.17.9', 'version')
    rows = [e for e in r['events'] if e['case'] != 'cluster_clock_probe']
    need([e['case'] for e in rows] == list(EXPECTED), 'case inventory/order')
    es = {e['case']: e for e in rows}
    for name, e in es.items():
        need(e['status'] == EXPECTED[name], 'status: ' + name)
        need(type(e['timestamp']) is int and e['timestamp'] > 0, 'event timestamp')
    expected_requests = {
        'pending_live': (10, 0, 2, 30, 10), 'post_live': (11, 10, 4, 0, 10),
        'application_ack_discard_retry': (11, 10, 4, 0, 10),
        'id_amount_conflict': (11, 10, 4, 0, 9), 'second_post': (12, 10, 4, 0, 10),
        'pending_void': (20, 0, 2, 30, 10), 'void_live': (21, 20, 8, 0, 0),
        'post_voided': (22, 20, 4, 0, 10), 'pending_expiring': (30, 0, 2, 1, 10),
        'post_expired': (31, 30, 4, 0, 10), 'void_expired': (32, 30, 8, 0, 0),
    }
    for name, expected in expected_requests.items():
        q = es[name]['request']
        need(tuple(q[k] for k in ('id','pending_id','flags','timeout','amount')) == expected, 'fixture: ' + name)
        need(q['timestamp'] == 0 and q['ledger'] == 1, 'nonimported fixture')
        if q['flags'] == 2: need(q['debit_account_id'] == 1 and q['credit_account_id'] == 2 and q['code'] == 1, 'accounts')
    need(es['post_live']['request'] == es['application_ack_discard_retry']['request'], 'exact retry')
    need(es['post_live']['timestamp'] == es['application_ack_discard_retry']['timestamp'], 'historical timestamp')
    need(es['post_live']['timestamp'] < es['pending_live']['timestamp'] + 30 * 10**9, 'live post deadline')
    expiry = es['pending_expiring']['timestamp'] + 10**9
    for name in ('post_expired', 'void_expired'): need(es[name]['timestamp'] >= expiry, 'cluster expiry')
    probes = [e for e in r['events'] if e['case'] == 'cluster_clock_probe']
    need(probes and max(e['timestamp'] for e in probes) >= expiry, 'cluster clock witness')
    before, after = r['before_restart'], r['after_restart']
    need(len(before) == 1 and before == after, 'immutable restart lookup')
    need(before[0]['id'] == 11 and before[0]['pending_id'] == 10 and before[0]['amount'] == 10 and before[0]['timestamp'] == es['post_live']['timestamp'], 'historical effect')
    accounts = {a['id']: a for a in r['accounts']}
    need(set(accounts) == {1, 2}, 'two accounts')
    need(accounts[1]['debits_posted'] == 10 and accounts[2]['credits_posted'] == 10 and accounts[1]['credits_posted'] == accounts[2]['debits_posted'] == 0, 'exactly one effect')
    return {'semantic_cases': 8, 'non_probe_events': len(rows), 'posted_effects': 1, 'scope': r['capability']}

def mutations(r):
    changed = []
    def add(path, value):
        x = copy.deepcopy(r); at = x
        for key in path[:-1]: at = at[key]
        at[path[-1]] = value; changed.append(x)
    add(['commit_deadline'], True)
    add(['capability'], 'COMMIT_DEADLINE')
    for i,e in enumerate(r['events']):
        if e['case'] != 'cluster_clock_probe':
            add(['events',i,'status'], 'FORGED_SUCCESS')
            add(['events',i,'request','amount'], e['request']['amount'] + 1)
    add(['after_restart',0,'timestamp'], 0)
    add(['accounts',0,'debits_posted'], 999)
    for x in changed:
        try: check(x)
        except (ValueError, KeyError, TypeError): continue
        raise ValueError('changed evidence accepted')
    return len(changed)

if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('capture', type=Path); a = p.parse_args()
    raw = a.capture.read_bytes(); r = json.loads(raw); result = check(r)
    result.update(capture_sha256=hashlib.sha256(raw).hexdigest(), mutations_rejected=mutations(r))
    print(json.dumps(result, sort_keys=True))
