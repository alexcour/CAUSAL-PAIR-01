"""Strict saved-evidence receiver. Imports no producer, engine or certifier code."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from shared import CASES, get, need


def identity(x):
    need(x['uid'] == x['euid'] == 62021 and x['no_new_privs'] == '1' and x['dumpable'] == 0
         and int(x['cap_eff'], 16) == 0, 'OWNER_IDENTITY')


def peer(r, uid):
    need(r['client_uid'] == uid and r['response']['peer'] == dict(pid=r['client_pid'], uid=uid, gid=uid), 'KERNEL_PEER')


def one(r, data, verify, canonical, content_hash):
    p, case = r['profile'], r['case']
    need(p in ('FCI', 'STANDARD') and case in CASES and r['status'] == 'CAPTURED_AWAITING_READER', 'CELL')
    w, certifier = data['writer'], data['certifier']
    c = w['context']
    rid = c['allocation_B']['rid']
    request = w['request_B']
    need(r['writer_ready']['request_B'] == request and r['writer_ready']['context'] == c, 'OWNER_PREPARED_BINDING')
    ca = verify(c['certificate'], c['sink_public'], b'FCI-NATIVE-NONEXECUTION-CERTIFICATE/1\0')
    need(ca['key'] == c['key'] and ca['content_hash'] == c['h'] == content_hash(c['content'])
         and ca['fenced_generation'] == 1, 'A_PREPARATION')
    for req, uid, g in ((c['request_A'], 62023, 1), (request, 62024, 2)):
        b = verify(req['permit'], c['sink_public'], b'SAME-K-NATIVE-BRIDGE-PERMIT/1\0')
        nb = verify(req['native']['authorization'], c['issuer_public'], b'FCI-SQL-D2A-AUTHZ/1\0')
        need(b['key'] == c['key'] and b['content_hash'] == c['h'] and b['generation'] == g
             and b['subject_uid'] == nb['subject_uid'] == uid and b['native_operation_id'] == nb['operation_id']
             and b['native_digest'] == hashlib.sha256(canonical(req['native'])).hexdigest(), 'SIGNED_REQUEST')
        need(all(nb[f] == c['content'][f] for f in ('target', 'action', 'expected_version', 'value')), 'NATIVE_CONTENT_BINDING')
        if g == 2:
            need(b['native_operation_id'] == rid and b['attempt_id'] == c['allocation_B']['attempt_id'], 'SIGNED_B_ALLOCATION')
    need(r['authority_inode_retained'] is r['private_pins_retained'] is True, 'RETAINED_AUTHORITY')
    for name, x in (('writer', w), ('certifier', certifier)):
        identity(x['identity'])
        ready = r[name + '_ready']
        need(ready['pid'] == x['pid'] and x['ppid'] == ready['ppid'] == r['supervisor_pid'], 'SIBLING_PROCESSES')
        identity(ready['identity'])
    need(w['pid'] != certifier['pid'] and certifier['no_engine'] is True
         and r['certifier_ready']['native_engine_constructed'] is False
         and r['writer_ready']['native_engine_constructed'] is True, 'REAL_WRITER_NEW_CERT_DELEGATE')
    need(w['actor'] == 62024 and certifier['actor'] == 62022, 'ACTOR_ROLES')
    peer(r['writer_rpc'], 62024)
    peer(r['control_rpc'], 62022)
    need(r['writer_rpc']['response']['ok'] is r['control_rpc']['response']['ok'] is True, 'RPC_FAILURE')
    need(r['writer_rpc']['response']['result'] == w['response'] and
         r['control_rpc']['response']['result'] == dict(response=certifier['response'], repeat=certifier['repeat']), 'RPC_BINDING')
    need([x['client_uid'] for x in r['denials']] == [62023, 62024, 62025], 'DENIAL_COVERAGE')
    for x, code in zip(r['denials'], ('CONTROL_ROLE', 'CONTROL_ROLE', 'UNKNOWN_UID')):
        peer(x, x['client_uid'])
        need(x['response']['ok'] is False and x['response']['error'] == code, 'ROLE_DENIAL')
    waits = r['waits']
    need([x['mode'] for x in waits] == ['writer', 'certifier'] + (['raw'] if case == 'RAW_SQL_CONTROL' else [])
         and all(x['waited'] is True and x['exit'] == 0 for x in waits), 'CLEANUP_WAITS')
    need([x['pid'] for x in waits[:2]] == [w['pid'], certifier['pid']], 'WAIT_PID_BINDING')
    for snap in (r['while_paused'], r['final'], r['after_guarded_writer']):
        need(snap['reader_uid'] == 0 and snap['reader_pid'] == r['supervisor_pid'] not in (w['pid'], certifier['pid']), 'SEPARATE_SQL_READBACK')
    pause = r['pause']
    need(pause['pid'] == w['pid'] and pause['uid'] == 62021 and r['while_paused']['business']['native_effects'] == []
         and r['while_paused']['business']['business_results'] == [], 'NO_EARLY_DURABLE_EFFECT')
    guard = [g for g in w['guard_observations'] if g.get('stage') == 'native_admission']
    need(len(guard) == 1 and guard[0]['in_transaction'] is True and guard[0]['generation'] == 2, 'ACTUAL_NATIVE_FINAL_GUARD')
    writer_events, ce = data['writer_events'], data['certifier_events']
    need(all(x['pid'] == w['pid'] and x['uid'] == 62021 for x in writer_events)
         and all(x['pid'] == certifier['pid'] and x['uid'] == 62021 for x in ce), 'EVENT_IDENTITIES')
    primary = [x for x in ce if x.get('call') == 'primary']
    attempt = next(x for x in primary if x['event'] == 'CERT_BEGIN_ATTEMPT')
    acquired = next(x for x in primary if x['event'] == 'CERT_BEGIN_ACQUIRED')
    returned = next(x for x in ce if x['event'] == 'PRIMARY_RETURNED')
    released = next(x for x in writer_events if x['event'] == 'WRITER_RELEASED')
    need(attempt['ns'] <= acquired['ns'] < returned['ns'] and pause['ns'] < attempt['ns'], 'CERT_SQL_ORDER')
    final = r['final']['business']
    need(final['business_rows'] == 1 and len(final['attempts']) == 2, 'NO_C')
    need(final['attempts'][0] == [1, 62023, ca['fenced_native_operation_id'], 'FENCED'], 'A_RETAINED')
    need(w['synthetic_bootstrap_before_B'] is True, 'DECLARED_BOOTSTRAP')
    if case == 'COMMIT_FIRST':
        pending = r['pending_control_observation']
        need(pause['point'] == 'before_commit' and pause['in_transaction'] is True and len(pause['staged_effects']) == 1
             and pause['staged_effects'][0][0] == rid, 'REAL_STAGED_NATIVE_EFFECT')
        need(pending['no_acquired_event'] is pending['writer_alive'] is pending['certifier_alive'] is pending['control_pending'] is True
             and attempt['ns'] < pending['ns'] < r['release_writer_ns'] <= released['ns'] <= acquired['ns'], 'CONCURRENT_SQL_BLOCKING')
        need(r['before_writer_release']['business']['native_effects'] == [], 'COMMIT_BEFORE_RELEASE')
        need(w['response']['status'] == 'NEW' and certifier['response']['disposition'] == 'RESULT_RETRIEVED'
             and certifier['repeat'] == certifier['response'], 'HISTORICAL_RESULT_ONLY')
        env = w['response']['result']
        b = verify(env, c['sink_public'], b'SAME-K-NATIVE-BRIDGE-RESULT/1\0')
        need(b['key'] == c['key'] and b['content_hash'] == c['h'] and b['native_operation_id'] == rid
             and b['generation'] == 2 and b['subject_uid'] == 62024, 'RESULT_BINDING')
        need(b['target'] == c['content']['target'] and b['value'] == c['content']['value']
             and b['old_version'] == c['content']['expected_version'] and b['new_version'] == b['old_version'] + 1,
             'RESULT_CONTENT')
        need(final['native_effects'] == [[rid, b['old_version'], b['new_version'], b['value']]]
             and final['business_results'] == [env] and certifier['response']['result'] == env, 'SQL_RESULT_EXACT')
        need(final['attempts'][1] == [2, 62024, rid, 'APPLIED'] and len(r['final']['certificates']) == 1, 'NO_FALSE_B_CERTIFICATE')
        need(r['final']['business'] == r['after_guarded_writer']['business'], 'FINAL_CHANGED')
        outcome = 'NATIVE_COMMIT_WINS_R0_ONLY'
    else:
        need(pause['point'] == 'after_precheck' and pause['in_transaction'] is False and r['writer_live_at_certificate'] is True,
             'OLD_OWNER_LIVE_OUTSIDE_TRANSACTION')
        commit = next(x for x in primary if x['event'] == 'CERT_COMMIT_RETURNED')
        need(commit['ns'] < returned['ns'] < r['release_writer_ns'] <= released['ns'], 'FENCE_BEFORE_NATIVE_RESUME')
        need(w['response'] == dict(status='REFUSED', code='STALE_ATTEMPT'), 'LATE_NATIVE_REFUSAL')
        need(not any(x['event'] == 'WRITER_COMMIT_RETURNED' for x in writer_events), 'OLD_EFFECT_COMMITTED')
        cert = certifier['response']['certificate']
        cb = verify(cert, c['sink_public'], b'FCI-NATIVE-NONEXECUTION-CERTIFICATE/1\0')
        need(cb['key'] == c['key'] and cb['content_hash'] == c['h'] and cb['fenced_generation'] == 2
             and cb['fenced_native_operation_id'] == rid and cb['fenced_subject_uid'] == 62024, 'CERTIFICATE_B_BINDING')
        need(certifier['response']['disposition'] == 'NONEXECUTION_CERTIFICATE_CREATED'
             and certifier['repeat'] == dict(disposition='NONEXECUTION_CERTIFICATE_RETRIEVED', certificate=cert), 'CERTIFICATE_REPLAY')
        need(len(r['final']['certificates']) == 2 and json.loads(r['final']['certificates'][1][1]) == cert
             and r['final']['certificates'][1][2:] == [0, None], 'CERT_B_UNUSED_NO_C')
        observed = r['after_certificate_while_writer_alive']
        need(observed['certificates'] == r['final']['certificates'] and observed['ns'] < r['release_writer_ns']
             and observed['business']['attempts'][1] == [2, 62024, rid, 'FENCED']
             and observed['business']['native_effects'] == observed['business']['business_results'] == [], 'DURABLE_FENCE_BEFORE_RESUME')
        safe = r['after_guarded_writer']['business']
        need(safe['native_effects'] == safe['business_results'] == [] and safe['attempts'][1] == [2, 62024, rid, 'FENCED'], 'ZERO_GUARDED_EFFECT')
        if case == 'FENCE_FIRST':
            need(final == safe, 'AFTER_FENCE_STATE_CHANGED')
            outcome = 'FENCE_WINS_NATIVE_CALLBACK_REFUSED'
        else:
            raw = data['raw']
            identity(raw['identity'])
            need(raw['pid'] == r['raw_ready']['pid'] == waits[2]['pid'] and raw['ppid'] == r['supervisor_pid']
                 and raw['pid'] not in (w['pid'], certifier['pid']) and raw['bypassed_mediated_API'] is True
                 and raw['native_execute_called'] is False, 'RAW_CONTROL_DOMAIN')
            re = data['raw_events']
            opened = next(x for x in re if x['event'] == 'RAW_OPEN')
            wrote = next(x for x in re if x['event'] == 'RAW_WRITE_BEGIN')
            done = next(x for x in re if x['event'] == 'RAW_COMMIT_RETURNED')
            need(opened['ns'] < attempt['ns'] and returned['ns'] < r['release_raw_ns'] <= wrote['ns'] < done['ns'], 'LIVE_RAW_HOLDER_ORDER')
            need(raw['before'] == safe['configuration'] and raw['after'] == final['configuration']
                 and final['configuration'] == [[c['content']['target'], 1, 1]], 'REAL_RAW_RESOURCE_CHANGE')
            need(final['native_effects'] == final['business_results'] == [] and
                 {k: v for k, v in final.items() if k != 'configuration'} == {k: v for k, v in safe.items() if k != 'configuration'},
                 'RAW_CONTROL_NOT_NATIVE_SUCCESS')
            need(r['final']['certificates'] == r['after_guarded_writer']['certificates'], 'CERTIFICATE_SIGNATURE_IS_NOT_GLOBAL_MEDIATION')
            outcome = 'PRIVILEGED_SQL_OUTSIDE_MEDIATION_DEMONSTRATED'
    return dict(profile=p, case=case, verdict='PASS_SCOPED', outcome=outcome,
        official_native_effects=len(final['native_effects']), raw_configuration_changed=case == 'RAW_SQL_CONTROL',
        fci_live_poisoned_after=w['after']['native_control'].get('poisoned') if p == 'FCI' else None)


def check(folder, support, mutations=False):
    sys.path.insert(0, str(Path(support) / 'fci-same-k-handoff-20261030'))
    from handoff import verify, canonical, content_hash
    rep = get(Path(folder) / 'RESULTS.json')
    need(rep['schema'] == 'LIVE-HOLDER-COMMIT/1' and rep['status'] == 'CAPTURED_AWAITING_READER'
         and rep['cases'] == rep['expected_cases'] == 6 and rep['failures'] == 0
         and get(Path(folder) / 'FAILURES.json') == [], 'INCOMPLETE_SUITE')
    for name, h in rep['own_sources'].items():
        need(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == h, 'OWN_SOURCE_CHANGED')
    pins = get(HERE / 'INPUTS.json')
    for x in pins['files']:
        prefix = x['argument'].removesuffix('_root')
        need(rep['copied_sources'].get(prefix + '/' + x['path']) == x['sha256'], 'COPIED_SOURCE_PIN')
    need(rep['copied_sources'].get('task/wire.py') == pins['wire']['sha256'], 'WIRE_PIN')
    manifest = get(Path(support) / 'fci-same-k-handoff-20261030/NATIVE_SOURCES.json')
    need(all(rep['copied_sources'].get('native/' + n) == h for n, h in manifest['files'].items()), 'FROZEN_37_SOURCES')
    need(all(rep['copied_sources'].get('task/' + n) == h for n, h in rep['own_sources'].items() if n.endswith('.py')), 'RUNTIME_OWN_SOURCE')
    results, originals = [], []
    for p in ('FCI', 'STANDARD'):
        for case in CASES:
            path = Path(folder) / (p + '__' + case)
            r = get(path / 'report.json')
            need((r['profile'], r['case']) == (p, case), 'CELL_BINDING')
            d = dict(writer=get(path / 'writer.json'), certifier=get(path / 'certifier.json'),
                writer_events=[json.loads(x) for x in (path / 'writer.jsonl').read_text().splitlines()],
                certifier_events=[json.loads(x) for x in (path / 'certifier.jsonl').read_text().splitlines()])
            if case == 'RAW_SQL_CONTROL':
                d.update(raw=get(path / 'raw.json'), raw_events=[json.loads(x) for x in (path / 'raw.jsonl').read_text().splitlines()])
            results.append(one(r, d, verify, canonical, content_hash))
            originals.append((r, d))
    need(sum(x['official_native_effects'] for x in results) == 2 and sum(x['raw_configuration_changed'] for x in results) == 2, 'COUNTS')
    rejected = []
    if mutations:
        changes = [
            (0, 'fake_blocking', lambda r, d: r['pending_control_observation'].update(control_pending=False)),
            (0, 'fake_native_transaction', lambda r, d: r['pause'].update(in_transaction=False)),
            (0, 'collapsed_processes', lambda r, d: d['certifier'].update(pid=d['writer']['pid'])),
            (0, 'bad_kernel_uid', lambda r, d: r['writer_rpc']['response']['peer'].update(uid=62022)),
            (0, 'lost_result', lambda r, d: r['final']['business'].update(business_results=[])),
            (0, 'bad_wait', lambda r, d: r['waits'][0].update(waited=False)),
            (1, 'no_final_guard', lambda r, d: d['writer'].update(guard_observations=[])),
            (1, 'bad_certificate', lambda r, d: d['certifier']['response']['certificate'].update(signature='0'*128)),
            (1, 'certificate_consumed', lambda r, d: r['final']['certificates'][1].__setitem__(2, 1)),
            (1, 'resume_before_commit', lambda r, d: r.update(release_writer_ns=0)),
            (2, 'raw_called_native', lambda r, d: d['raw'].update(native_execute_called=True)),
            (2, 'raw_change_hidden', lambda r, d: r['final']['business'].update(configuration=r['after_guarded_writer']['business']['configuration'])),
        ]
        for index, name, mutate in changes:
            r, d = copy.deepcopy(originals[index])
            mutate(r, d)
            try:
                one(r, d, verify, canonical, content_hash)
            except (ValueError, KeyError, TypeError, StopIteration):
                rejected.append(name)
            else:
                raise ValueError('MUTANT_ACCEPTED:' + name)
    return dict(status='RECEIVED_SCOPED_LIVE_NATIVE_WRITER_CERTIFIER', results=results,
        cells=6, role_denials=18, saved_mutants_rejected=len(rejected), mutants=rejected,
        native_effects=2, privileged_raw_controls=2, full_no_bypass=False,
        full_authority_restore=False, comparative_advantage=False, M1='HOLD')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('folder', type=Path)
    p.add_argument('--support-root', type=Path, required=True)
    p.add_argument('--mutations', action='store_true')
    a = p.parse_args()
    print(json.dumps(check(a.folder, a.support_root, a.mutations), sort_keys=True))
