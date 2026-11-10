"""Actual concurrent native writer and certificate-only SQL delegate."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from snapshots import root_snapshot
from shared import OWNER, CONTROL, A, B, UNKNOWN, CASES, ROOTS, get, put, need, setup, arguments, root_flags, python, until, events, commit_race


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(args, code, mode):
    return python() + [str(code / 'actors.py')] + root_flags(args) + ['--mode', mode,
        '--profile', args.profile, '--case', args.case,  '--runtime', str(args.runtime),
        '--work', str(args.work), '--socket', str(args.folder / 'socket' / mode)]


def start(args, code, mode, out):
    log = (out / (mode + '.stderr')).open('w')
    p = subprocess.Popen(command(args, code, mode), user=OWNER, group=OWNER, extra_groups=(),
        umask=0o077, stdout=subprocess.PIPE, stderr=log, text=True)
    with selectors.DefaultSelector() as select:
        select.register(p.stdout, selectors.EVENT_READ)
        ready = bool(select.select(10))
    line = p.stdout.readline() if ready else ''
    log.close()
    if not line:
        p.terminate()
        p.communicate(timeout=5)
        raise ValueError('ACTOR_NOT_READY:' + mode + ':' + (out / (mode + '.stderr')).read_text()[-2500:])
    value = json.loads(line)
    need(value['ready'] and value['pid'] == p.pid, 'READY_PID')
    return p, value


def probe(args, code, endpoint, uid, op):
    p = subprocess.Popen(python() + [str(code / 'wire.py'), '--socket', str(args.folder / 'socket' / endpoint)],
        user=uid, group=uid, extra_groups=(), umask=0o077, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p.stdin.write(json.dumps(dict(op=op, args={})))
    p.stdin.close()
    p.stdin = None
    return p


def answer(p):
    try:
        out, err = p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        raise ValueError('RPC_TIMEOUT')
    need(p.returncode == 0, 'RPC_CLIENT:' + err[-2000:])
    return json.loads(out)


def snapshot(native, args):
    core = args.runtime / ('consumer.db' if args.profile == 'FCI' else 'resource.db')
    with sqlite3.connect('file:' + str(core) + '?mode=ro', uri=True) as db:
        certs = [list(x) for x in db.execute('SELECT g,envelope,redeemed,allocation FROM sk_certificates ORDER BY g')]
    return dict(diagnostic=root_snapshot(args.runtime, args.profile), business=json.loads(json.dumps(native.observe(args.runtime, args.profile))), certificates=certs,
                reader_pid=os.getpid(), reader_uid=os.getuid(), ns=time.monotonic_ns())


def cell(args, code, top, out):
    parent, native, _ = setup(args)
    args.folder = top / (args.profile + '__' + args.case)
    args.folder.mkdir(mode=0o755)
    args.runtime = native.provision(args.native_root, args.folder, args.profile)
    args.runtime.chmod(0o700)
    args.work = args.folder / 'work'
    args.work.mkdir(mode=0o700)
    os.chown(args.work, OWNER, OWNER)
    sd = args.folder / 'socket'
    sd.mkdir(mode=0o755)
    os.chown(sd, OWNER, OWNER)
    core = args.runtime / ('consumer.db' if args.profile == 'FCI' else 'resource.db')
    inode = core.stat().st_ino
    pins = {p.name: sha(p) for p in args.runtime.iterdir() if p.suffix in ('.key', '.json')}
    processes, clients = [], []
    row = dict(profile=args.profile, case=args.case, status='INCONCLUSIVE', supervisor_pid=os.getpid(),
               waits=[], denials=[])
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from handoff import public
        private = get(args.runtime / 'bridge-private.json')
        row['trust_anchors'] = {n:public(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private[n]))) for n in ('issuer','sink')}
        first = subprocess.run(python() + [str(args.recovery_root / 'run_recovery.py'), '--child', '--phase', 'fault',
            '--case', 'live_holder_preparation', '--profile', args.profile, '--runtime', str(args.runtime),
            '--work', str(args.work), '--native-root', str(args.native_root), '--support-root', str(args.support_root),
            '--reference-root', str(args.reference_root)], user=OWNER, group=OWNER, extra_groups=(), umask=0o077,
            capture_output=True, text=True, timeout=25)
        need(first.returncode == 0, 'PREPARATION:' + first.stderr[-2200:])
        fault = get(args.work / 'fault.json')
        put(args.work / 'supervisor.json', dict(old_process_waited=True, old_exit=0, old_pid=fault['pid'],
            single_owner_no_clones=True, authority_inode=inode))
        os.chown(args.work / 'supervisor.json', OWNER, OWNER)
        (args.work / 'supervisor.json').chmod(0o600)
        row['preparation'] = fault
        writer, ready = start(args, code, 'writer', out)
        processes.append(('writer', writer))
        row['writer_ready'] = ready
        row['writer_role_denials'] = []
        for uid, expected in ((A, 'WRITER_ROLE'), (CONTROL, 'WRITER_ROLE'), (UNKNOWN, 'UNKNOWN_UID')):
            bad = probe(args, code, 'writer', uid, 'execute_B')
            clients.append(bad)
            denied = answer(bad)
            need(denied['response']['ok'] is False and denied['response']['error'] == expected, 'WRITER_CREDENTIAL_DENIAL')
            row['writer_role_denials'].append(denied)
        old = probe(args, code, 'writer', B, 'execute_B')
        clients.append(old)
        until(lambda: (args.work / 'paused.json').exists(), 'NATIVE_PAUSE')
        row['pause'] = get(args.work / 'paused.json')
        row['while_paused'] = snapshot(native, args)
        certifier, cert_ready = start(args, code, 'certifier', out)
        processes.append(('certifier', certifier))
        row['certifier_ready'] = cert_ready
        if args.case == 'RAW_SQL_CONTROL':
            raw, raw_ready = start(args, code, 'raw', out)
            processes.append(('raw', raw))
            row['raw_ready'] = raw_ready
        for uid, code_expected in ((A, 'CONTROL_ROLE'), (B, 'CONTROL_ROLE'), (UNKNOWN, 'UNKNOWN_UID')):
            bad = probe(args, code, 'certifier', uid, 'certify_B')
            clients.append(bad)
            denied = answer(bad)
            need(denied['response']['ok'] is False and denied['response']['error'] == code_expected, 'ROLE_DENIAL')
            row['denials'].append(denied)
        control = probe(args, code, 'certifier', CONTROL, 'certify_B')
        clients.append(control)
        until(lambda: any(x['event'] == 'CERT_BEGIN_ATTEMPT' and x.get('call') == 'primary'
                          for x in events(args.work / 'certifier.jsonl')), 'CERT_BEGIN')
        if commit_race(args.case):
            # Diagnostic observation while a real BEGIN IMMEDIATE is pending.
            time.sleep(.15)
            e = events(args.work / 'certifier.jsonl')
            need(not any(x['event'] in ('CERT_BEGIN_ACQUIRED', 'PRIMARY_RETURNED') for x in e), 'CERTIFIER_PASSED_LIVE_WRITER')
            need(writer.poll() is certifier.poll() is control.poll() is None, 'NOT_CONCURRENT')
            row['pending_control_observation'] = dict(ns=time.monotonic_ns(), no_acquired_event=True,
                writer_alive=True, certifier_alive=True, control_pending=True)
            row['before_writer_release'] = snapshot(native, args)
            row['release_writer_ns'] = time.monotonic_ns()
            (args.work / 'release-writer').touch()
            row['writer_rpc'] = answer(old)
            row['control_rpc'] = answer(control)
        else:
            row['control_rpc'] = answer(control)
            need(writer.poll() is None, 'OLD_NATIVE_OWNER_NOT_LIVE')
            row['writer_live_at_certificate'] = True
            if args.case == 'BAD_CERTIFICATE':
                with sqlite3.connect('file:' + str(core) + '?mode=rw', uri=True) as db:
                    value = json.loads(db.execute('SELECT envelope FROM sk_certificates WHERE g=2').fetchone()[0])
                    row['certificate_before_tamper'] = copy.deepcopy(value)
                    value['signature'] = '0' * 128
                    db.execute('UPDATE sk_certificates SET envelope=? WHERE g=2', (json.dumps(value,sort_keys=True,separators=(',',':')),))
                row['certificate_fault'] = 'STORED_SIGNATURE_ONLY_AFTER_CERTIFICATE_BEFORE_RESUME'
            row['after_certificate_while_writer_alive'] = snapshot(native, args)
            row['release_writer_ns'] = time.monotonic_ns()
            (args.work / 'release-writer').touch()
            row['writer_rpc'] = answer(old)
        need(row['writer_rpc']['response']['ok'] is row['control_rpc']['response']['ok'] is True, 'RPC_HOLD')
        row['after_guarded_writer'] = snapshot(native, args)
        if args.case == 'RAW_SQL_CONTROL':
            need(writer.poll() is raw.poll() is None, 'RAW_HOLDER_NOT_LIVE')
            row['release_raw_ns'] = time.monotonic_ns()
            (args.work / 'release-raw').touch()
            raw.communicate(timeout=8)
            need(raw.returncode == 0, 'RAW_CHILD')
            row['raw'] = get(args.work / 'raw.json')
        row['final'] = snapshot(native, args)
        need(core.stat().st_ino == inode and pins == {p.name: sha(p) for p in args.runtime.iterdir() if p.suffix in ('.key', '.json')},
             'AUTHORITY_OR_PRIVATE_PINS_CHANGED')
        row.update(status='CAPTURED_AWAITING_READER', authority_inode_retained=True, private_pins_retained=True)
    except Exception:
        row['error'] = traceback.format_exc()
        raise
    finally:
        for name in ('release-writer', 'release-raw', 'stop'):
            (args.work / name).touch()
        for p in clients:
            if p.poll() is None:
                p.terminate()
            try:
                p.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.communicate()
        for mode, p in processes:
            try:
                p.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                p.kill()
                p.communicate()
            row['waits'].append(dict(mode=mode, pid=p.pid, exit=p.returncode, waited=True))
        for p in args.work.iterdir():
            if p.is_file() and p.suffix in ('.json', '.jsonl'):
                shutil.copyfile(p, out / p.name)
        put(out / 'report.json', row)
        shutil.rmtree(args.folder)
    return row


def run(args):
    args.out.mkdir(parents=True, exist_ok=False)
    maps = {k: [list(map(int, x.split())) for x in Path('/proc/self/' + k + '_map').read_text().splitlines()] for k in ('uid', 'gid')}
    report = dict(schema='LIVE-HOLDER-COMMIT/1', status='NOT_RUN', cases=0, uid_maps=maps,
        optimized=not __debug__, campaign='TYPED-REFUSAL-NATIVE/1', M1='HOLD', own_sources={p.name: sha(p) for p in HERE.iterdir() if p.is_file() and not p.name.startswith('pinned-example-')})
    put(args.out / 'RESULTS.json', report)
    if os.geteuid() != 0 or not all(any(lo <= uid < lo + n for lo, _, n in maps[k]) for k in maps for uid in range(OWNER, UNKNOWN + 1)):
        report['status'] = 'NOT_RUN_HOST_UIDS_UNAVAILABLE'
        put(args.out / 'RESULTS.json', report)
        return 3
    for x in get(HERE / 'INPUTS.json')['files']:
        data = (getattr(args, x['argument']) / x['path']).read_bytes()
        need(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == x['git_blob'], 'SOURCE_PIN:' + x['path'])
    wire = args.wire_source.read_bytes()
    need(hashlib.sha1(b'blob ' + str(len(wire)).encode() + b'\0' + wire).hexdigest() ==
         get(HERE / 'INPUTS.json')['wire']['git_blob'], 'WIRE_SOURCE_PIN')
    parent, native, _ = setup(args)
    manifest = native.checked_sources(args.native_root)
    failures, rows = [], []
    with tempfile.TemporaryDirectory(prefix='live-holder-') as temp:
        top = Path(temp)
        top.chmod(0o755)
        local = copy.copy(args)
        groups = [('native', args.native_root, tuple(manifest['files'])),
            ('support', args.support_root, tuple('fci-same-k-handoff-20261030/' + x for x in ('run_native_bridge.py', 'native_bridge.py', 'handoff.py', 'uds_service.py', 'NATIVE_SOURCES.json'))),
            ('reference', args.reference_root, ('certified_bridge.py',)),
            ('recovery', args.recovery_root, ('run_recovery.py', 'recovery.py')),
            ('task', HERE, tuple(p.name for p in HERE.glob('*.py')))]
        for name, src, names in groups:
            dest = top / name
            for n in names:
                target = dest / n
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src / n, target)
                target.chmod(0o444)
            if name in ROOTS:
                setattr(local, name + '_root', dest)
        shutil.copyfile(args.wire_source, top / 'task' / 'wire.py')
        (top / 'task' / 'wire.py').chmod(0o444)
        for p in top.rglob('*'):
            if p.is_dir():
                p.chmod(0o755)
        copied = {str(p.relative_to(top)): sha(p) for p in top.rglob('*') if p.is_file()}
        for profile in ('FCI', 'STANDARD'):
            for case in CASES:
                local.profile, local.case = profile, case
                out = args.out / (profile + '__' + case)
                out.mkdir()
                try:
                    rows.append(cell(local, top / 'task', top, out))
                    print(profile, case, 'CAPTURED', flush=True)
                except Exception:
                    failures.append(dict(profile=profile, case=case, error=traceback.format_exc()))
                    print(profile, case, failures[-1]['error'], flush=True)
                    break
            if failures:
                break
        native.checked_sources(args.native_root)
        native.checked_sources(top / 'native')
        need(all(sha(top / p) == h for p, h in copied.items()), 'SOURCE_CHANGED')
        report.update(status='CAPTURED_AWAITING_READER' if not failures else 'FAILURE', cases=len(rows), expected_cases=len(CASES)*2,
            failures=len(failures), copied_sources=copied, frozen_engine_files_modified=False,
            certificate_method_modified=False, certification_delegate_new=True, native_writer_constructor=True,
            full_authority_restored=False, universal_no_bypass=False, comparative_advantage=False)
    put(args.out / 'RESULTS.json', report)
    put(args.out / 'FAILURES.json', failures)
    return int(bool(failures))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    arguments(p)
    p.add_argument('--wire-source', type=Path)
    p.add_argument('--out', type=Path, required=True)
    sys.exit(run(p.parse_args()))
