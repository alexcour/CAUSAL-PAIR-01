"""Two sibling owner-UID processes: genuine native writer and cert-only delegate.

Root/OS/owner and both trusted delegates remain in the trusted computing base.
The RAW_SQL_CONTROL actor intentionally writes outside the mediated API.
"""
import argparse
from contextlib import nullcontext
import hashlib
import uuid
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from participant import Participant
from snapshots import actor_snapshot
from shared import OWNER, CONTROL, B, A, ROOTS, get, put, need, setup, arguments, until, commit_race


def run(args):
    parent, native, Bridge = setup(args)
    sys.path[:0]=[str(args.native_root.parent/'retirement'),str(args.native_root.parent/'crash')]
    sys.path.insert(0,str(args.native_root.parent/'admission'))
    from attribution import augment
    Bridge = augment(Bridge)
    from uds_service import Service, harden, directory, private_file
    from handoff import Refused, canonical, public, shape
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    identity = harden()
    need(os.getuid() == os.geteuid() == OWNER, 'OWNER_UID')
    directory(args.runtime, OWNER, 0o700)
    directory(args.work, OWNER, 0o700)
    c = get(args.work / 'context.json')
    logfile = args.work / (args.mode + '.jsonl')

    def emit(event, **fields):
        with logfile.open('a') as out:
            out.write(json.dumps(dict(event=event, ns=time.monotonic_ns(), pid=os.getpid(),
                ppid=os.getppid(), uid=os.getuid(), mode=args.mode, **fields)) + '\n')
            out.flush()
            os.fsync(out.fileno())

    if args.mode == 'raw':
        # Explicit privileged delegation in a fresh disposable lab fixture.
        core = args.runtime / ('consumer.db' if args.profile == 'FCI' else 'resource.db')
        table = 'demo_configuration' if args.profile == 'FCI' else 'configuration'
        with sqlite3.connect('file:' + str(core) + '?mode=rw', uri=True, isolation_level=None) as db:
            before = db.execute('SELECT target,version,value FROM ' + table).fetchall()
            emit('RAW_OPEN', in_transaction=db.in_transaction)
            print(json.dumps(dict(ready=True, pid=os.getpid(), ppid=os.getppid(), identity=identity)), flush=True)
            until(lambda: (args.work / 'release-raw').exists(), 'RAW_RELEASE', 20)
            db.execute('BEGIN IMMEDIATE')
            emit('RAW_WRITE_BEGIN', in_transaction=db.in_transaction)
            db.execute('UPDATE ' + table + ' SET value=1,version=version+1 WHERE target=? AND version=0', (c['content']['target'],))
            need(db.execute('SELECT changes()').fetchone()[0] == 1, 'RAW_ONE_ROW')
            db.execute('COMMIT')
            after = db.execute('SELECT target,version,value FROM ' + table).fetchall()
            emit('RAW_COMMIT_RETURNED', in_transaction=db.in_transaction)
            put(args.work / 'raw.json', dict(pid=os.getpid(), ppid=os.getppid(), identity=identity,
                before=before, after=after, bypassed_mediated_API=True, native_execute_called=False))
        return

    keys = json.loads(private_file(args.runtime / 'bridge-private.json', OWNER, 0o600))
    sink = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys['sink']))
    b = None
    if args.mode == 'writer':
        signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys['issuer']))
        b = Bridge(args.native_root, args.runtime, args.profile, signer, sink)
        from recovery import recovery_gate, safe_rearm
        gate = recovery_gate(b, c, CONTROL, get(args.work / 'supervisor.json'))
        need(gate['status'] == 'CONSISTENT_FOR_SUPERVISED_REARM', 'PRE_B_GATE')
        helper = safe_rearm(b, CONTROL)
        need(helper['status'] == 'READY', 'PRE_B_REARM')
        request = b.issue(c['allocation_B'], CONTROL)
        b.prepare_attribution(request, B)
        ready = dict(ready=True, pid=os.getpid(), ppid=os.getppid(), identity=identity,
            request_B=request, context=c, policy=b.policy, deployment=b.deployment,
            producer_authorization=b.producer_authorization,
            gate=gate, helper=helper, native_engine_constructed=True)
        put(args.work / 'prepared.json', ready)
    else:
        from cert_view import CertificateView
        from native_bridge import load_native
        _, _, auth = load_native(args.native_root)
        prepared = get(args.work / 'prepared.json')
        active_call = ['primary']
        view = CertificateView(args.runtime, args.profile, prepared['deployment'], prepared['policy'], sink,
                               auth, trace=lambda event: emit(event, call=active_call[0]))
        ready = dict(ready=True, pid=os.getpid(), ppid=os.getppid(), identity=identity,
                     native_engine_constructed=False, certificate_only_delegate=True)

    def pause(point):
        if point != args.cut:
            return
        if point=='before_commit' and args.profile=='FCI' and not getattr(b,'retirement_after_reservation',False):
            return
        import signal
        from participant import tables
        put(args.work / 'kill-marker.json', dict(point=point,pid=os.getpid(),uid=os.getuid(),
            in_transaction=b.db.in_transaction,retirement_reservation_cut=getattr(b,'retirement_after_reservation',False),participant=b.producer_participant.evidence(),
            producer_authorization=b.producer_authorization,request=request,main=tables(b.db)))
        signal.pause()
        raise RuntimeError('SIGKILL_PAUSE_INTERRUPTED')

    if b is not None and args.profile=='FCI':
        original_consumer_finish=b.engine.consumer.finish
        def after_reservation_finish(rid,anchor,clock,conditions,hook=None):
            def mark(point):
                if hook is not None:hook(point)
                if point=='after_commit_fence' and args.cut=='before_commit':
                    b.retirement_after_reservation=True
                    pause('before_commit')
            return original_consumer_finish(rid,anchor,clock,conditions,hook=mark)
        b.engine.consumer.finish=after_reservation_finish

    class Endpoint(Service):
        def __init__(self):
            self.roles = {CONTROL: CONTROL, A: A, B: B}
        def dispatch(self, req, uid):
            shape(req, ('op', 'args'))
            shape(req['args'], ())
            if args.mode == 'writer':
                if req['op'] != 'execute_B' or uid != B:
                    raise Refused('WRITER_ROLE')
                emit('EXECUTE_ENTERED', actor=uid)
                row = dict(identity=identity, pid=os.getpid(), ppid=os.getppid(), context=c,
                           request_B=request, actor=uid, before=parent.state(b), synthetic_bootstrap_before_B=True)
                b.fault = pause
                row['diagnostic_before'] = actor_snapshot(b)
                participant = None if args.case == 'FROZEN_CONTROL' else Participant(b, case=args.case)
                b.producer_participant = participant
                try:
                    response = (b.execute if participant is None else participant.execute)(request, uid,
                        after_precheck=lambda: pause('after_precheck'))
                except b.auth.AuthorizationRefused as exc:
                    response = dict(status='REFUSED', code=str(exc))
                row['participant_disabled'] = participant is None
                row['participant'] = None if participant is None else participant.evidence()
                until(lambda: (args.work / 'certifier.json').exists(), 'CERTIFICATE_FINISHED_BEFORE_POST_SNAPSHOT', 20)
                emit('POST_SNAPSHOT_CERTIFIER_BARRIER_PASSED')
                row['diagnostic_after'] = actor_snapshot(b)
                row.update(response=response, after=parent.state(b), guard_observations=b.guard_observations)
                put(args.work / 'writer.json', row)
                emit('EXECUTE_RETURNED', status=response['status'])
                return response
            if req['op'] != 'certify_B' or uid != CONTROL:
                raise Refused('CONTROL_ROLE')
            emit('CERTIFY_ENTERED', actor=uid)
            active_call[0] = 'primary'
            answer = view.certify_nonexecution(c['key'], c['h'], 2, A, uid)
            emit('PRIMARY_RETURNED', disposition=answer['disposition'])
            active_call[0] = 'repeat'
            repeat = view.certify_nonexecution(c['key'], c['h'], 2, A, uid)
            put(args.work / 'certifier.json', dict(identity=identity, pid=os.getpid(), ppid=os.getppid(), actor=uid,
                response=answer, repeat=repeat, no_engine=True, trusted_delegate=True))
            emit('CERTIFY_RETURNED', disposition=answer['disposition'])
            return dict(response=answer, repeat=repeat)

    server = Endpoint()
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        listener.bind(str(args.socket))
        os.chmod(args.socket, 0o666)
        listener.listen(8)
        listener.settimeout(.1)
        print(json.dumps(ready), flush=True)
        try:
            while not (args.work / 'stop').exists():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                server.handle(conn)
        finally:
            if b is not None:
                b.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    arguments(p)
    for name in ('runtime', 'work', 'socket'):
        p.add_argument('--' + name, type=Path, required=name != 'socket')
    p.add_argument('--mode', choices=('writer', 'certifier', 'raw'), required=True)
    p.add_argument('--profile', choices=('FCI', 'STANDARD'), required=True)
    p.add_argument('--case', required=True)
    p.add_argument('--cut',choices=('before_commit','after_commit'),required=True)
    run(p.parse_args())
