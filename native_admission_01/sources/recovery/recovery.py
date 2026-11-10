"""Bounded owner-API recovery candidate. Never changes poison/recovery directly.

Not an RPC authorization API. Trusted supervisor must have waited for the old
single owner process, retained every authority store, and excluded live clones.
The gate is scoped to one business key/two attempts. Any wider scope holds.
"""
import hashlib
import json
import os

from handoff import canonical, content_hash, key_text, public, verify
from certified_bridge import DOMAIN, FIELDS


class RecoveryHeld(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise RecoveryHeld(code)


def rearm_view(reply):
    # A refusal is a valid response, never an incomplete REARM_STATE.
    if type(reply) is not dict or reply.get('code') != 'REARM_STATE':
        return dict(status='HOLD', code=(reply.get('code', 'MALFORMED_RESPONSE')
                    if type(reply) is dict else 'MALFORMED_RESPONSE'), native=reply)
    if (set(reply) != {'code', 'authority', 'consumer', 'now'} or
            type(reply['authority']) is not dict or type(reply['consumer']) is not dict or
            type(reply['authority'].get('mask')) is not int or
            type(reply['consumer'].get('mask')) is not int):
        return dict(status='HOLD', code='MALFORMED_REARM_STATE', native=reply)
    return dict(status='VIEW', native=reply)


def safe_rearm(bridge, actor):
    need(type(actor) is int and actor == bridge.controller, 'CONTROL_ROLE')
    s = bridge.engine
    replies = []
    if bridge.profile == 'FCI':
        from fci_hardened.service import clock
        from base01.authority import State, fixture_witness
        from lifecycle import Local, fixture_rearm
        # These remain synthetic fixture witnesses, not an independent oracle.
        keys = {k: bytes.fromhex(v) for k, v in json.loads(
                (bridge.runtime / 'keys.json').read_text()).items()}
        for part, op, accepted in (('authority', 'rearm_authority', 'REARM_ACCEPTED'),
                                   ('consumer', 'rearm_local', 'REARM_LOCAL_ACCEPTED')):
            reply = s.handle(actor, canonical(dict(op='rearm_state')))
            replies.append(reply)
            view = rearm_view(reply)
            if view['status'] != 'VIEW':
                return dict(status='HOLD', code=view['code'], replies=replies)
            if reply[part]['mask']:
                witness = (fixture_witness(State(**reply[part]), keys['rearm'], clock())
                           if part == 'authority' else
                           fixture_rearm(Local(**reply[part]), keys['local_rearm'], clock()))
                answer = s.handle(actor, canonical(dict(op=op, witness=witness)))
                replies.append(answer)
                if type(answer) is not dict or answer.get('code') != accepted:
                    return dict(status='HOLD', code=answer.get('code', 'MALFORMED_RESPONSE')
                                if type(answer) is dict else 'MALFORMED_RESPONSE', replies=replies)
        if s.authority_status() != 'READY':
            return dict(status='HOLD', code='NATIVE_NOT_READY', replies=replies)
    else:
        witness = s.witness()
        answer = s.rearm(witness, list(witness['causes']))
        replies.append(answer)
        if answer.get('code') != 'REARMED' or s.control()[1] or s.witness()['causes']:
            return dict(status='HOLD', code=answer.get('code', 'NATIVE_NOT_READY'), replies=replies)
    return dict(status='READY', code='NATIVE_READY', replies=replies)


def verify_snapshot(snapshot, context, pinned_public):
    """Read-only bounded consistency gate. A PASS is NOT an effect permit."""
    s, c = snapshot, context
    cert, alloc = c['certificate'], c['allocation_B']
    body = verify(cert, pinned_public, DOMAIN)
    need(set(body) == set(FIELDS), 'CERTIFICATE_SHAPE')
    k, h = c['key'], c['h']
    need(body['schema'] == 'NATIVE-NONEXECUTION-CERTIFICATE/1' and
         body['disposition'] == 'NONEXECUTION_FENCED' and
         body['key'] == k and body['content_hash'] == h and
         body['sink_public'] == pinned_public, 'CERTIFICATE_BINDING')
    need(s['policy'] == body['policy'] and s['revoked'] == 0 and
         s['epoch'] == body['epoch_at_fence'], 'AUTHORITY_CHANGED')
    need(s['key'] == k and s['h'] == h and content_hash(s['content']) == h and
         s['result'] is None and s['business_count'] == 1, 'BUSINESS_STATE')
    need(alloc['key'] == k and alloc['h'] == h and alloc['generation'] == body['fenced_generation']+1 and
         alloc['uid'] == body['successor_uid'], 'ALLOCATION_BINDING')
    need(s['attempts'] == [[body['fenced_generation'], body['fenced_attempt_id'],
                          body['fenced_subject_uid'], body['fenced_native_operation_id'], 'FENCED'],
                         [alloc['generation'], alloc['attempt_id'], alloc['uid'], alloc['rid'], 'OPEN']] and
         s['attempt_count'] == 2, 'FENCE_OR_SUCCESSOR')
    need(s['certificates'] == [[body['certificate_id'], key_text(k), body['fenced_generation'], h,
                               canonical(cert).decode(), 1, canonical(alloc).decode()]], 'CERTIFICATE_STORE')
    need(s['certificate_events'] == [['FENCE_AND_CERTIFICATE', body['certificate_id'], canonical(cert).decode()],
                                    ['CERTIFICATE_REDEEMED', body['certificate_id'], canonical(alloc).decode()]],
         'CERTIFICATE_EVENTS')
    need(s['effect_count'] == 0 and s['target_version'] == s['content']['expected_version'], 'EFFECT_OR_PRECONDITION')
    need(s['native_records_ok'] is True, 'NATIVE_RECORDS_UNRESOLVED')
    return dict(status='CONSISTENT_FOR_SUPERVISED_REARM', execution_authorized=False,
                snapshot_sha256=hashlib.sha256(canonical(s)).hexdigest())


def recovery_gate(bridge, context, actor, supervisor):
    need(type(actor) is int and actor == bridge.controller, 'CONTROL_ROLE')
    need(supervisor['old_process_waited'] is True and supervisor['old_exit'] in (0, 86) and
         supervisor['old_pid'] != os.getpid() and supervisor['single_owner_no_clones'] is True,
         'QUIESCENCE_NOT_ESTABLISHED')
    need(bridge.active is None and not bridge.db.in_transaction, 'OWNER_NOT_QUIESCENT')
    need(os.stat(bridge.path).st_ino == supervisor['authority_inode'], 'AUTHORITY_REPLACED')
    need(context['key']['deployment'] == bridge.deployment and context['key']['sink'] == bridge.profile,
         'SINK_DEPLOYMENT')
    old_rid = context['certificate']['body']['fenced_native_operation_id']
    with bridge.open_control() as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            need(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'SQL_INTEGRITY')
            kt = key_text(context['key'])
            row = db.execute('SELECT content,h,result FROM sk_business WHERE k=?', (kt,)).fetchone()
            need(row is not None, 'BUSINESS_MISSING')
            policy, epoch, revoked = bridge.control(db)
            native_ok = False
            if bridge.profile == 'FCI':
                records = db.execute('SELECT operation_id,phase FROM d2_operations ORDER BY operation_id').fetchall()
                native_ok = records in ([(old_rid, 'PREPARED')], [(old_rid, 'QUARANTINED')])
                # Authenticate native history with the native decoder; don't infer
                # nonexecution from a missing application row alone.
                entries = bridge.engine.consumer.history()
                native_ok = native_ok and len(entries) == 1 and entries[0]['status'] in ('PENDING', 'CANCELLED')
                op = bridge.engine.operation_row(old_rid)
                need(op is not None, 'NATIVE_OPERATION_MISSING')
                envelope = json.loads(op[0])
                need(bridge.auth.verify_signature(envelope, bridge.engine.public_key) == op[1] and
                     envelope == context['request_A']['native']['authorization'] and
                     op[2] == context['certificate']['body']['fenced_subject_uid'], 'NATIVE_OPERATION_BINDING')
            else:
                records = bridge.engine.ref.execute('SELECT operation_id,digest,envelope,phase FROM attempts').fetchall()
                native_ok = len(records) == 1 and records[0][0] == old_rid and records[0][3] == 'QUARANTINED'
                if native_ok:
                    env = json.loads(records[0][2])
                    native_ok = (env == context['request_A']['native']['authorization'] and
                                 bridge.auth.verify_signature(env, bridge.engine.key) == records[0][1])
            content = json.loads(row[0])
            target = db.execute('SELECT version FROM '+bridge.table+' WHERE target=?', (content['target'],)).fetchone()
            snap = dict(policy=policy, epoch=epoch, revoked=revoked, key=context['key'], h=row[1], content=content,
                        result=row[2], business_count=db.execute('SELECT count(*) FROM sk_business').fetchone()[0],
                        attempts=[list(x) for x in db.execute('SELECT g,attempt_id,uid,rid,state FROM sk_attempts WHERE k=? ORDER BY g', (kt,))],
                        attempt_count=db.execute('SELECT count(*) FROM sk_attempts').fetchone()[0],
                        certificates=[list(x) for x in db.execute('SELECT * FROM sk_certificates ORDER BY id')],
                        certificate_events=[list(x) for x in db.execute('SELECT event,certificate_id,payload FROM sk_certificate_events ORDER BY seq')],
                        effect_count=db.execute('SELECT count(*) FROM '+bridge.effects).fetchone()[0],
                        target_version=target[0] if target else None, native_records_ok=bool(native_ok))
            result = verify_snapshot(snap, context, public(bridge.sink_key))
            db.rollback()  # Gate writes no authority or recovery state.
            return dict(result, snapshot=snap)
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise
