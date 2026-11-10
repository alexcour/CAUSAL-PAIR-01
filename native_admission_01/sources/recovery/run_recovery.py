"""Disposable two-process experiment, frozen native engines, no automatic repair.

Root provisions fixtures and waits; only dedicated hardened UID62021 runs engines.
Normal/-O are repetitions. SQL mutations below are explicit fault injections.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import traceback

HERE = Path(__file__).resolve().parent
CASES = ('helper_only', 'supervised_restart', 'missing_certificate', 'wrong_actor',
         'authority_revoked', 'native_conditions_false', 'effect_divergence',
         'crash_before_rearm', 'crash_after_rearm')


def put(path, value):
    data = json.dumps(value, sort_keys=True, allow_nan=False).encode()
    with path.open('wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())


def setup(args):
    sys.path[:0] = [str(args.support_root / 'fci-same-k-handoff-20261030'), str(args.reference_root), str(HERE)]
    import run_native_bridge as native
    from certified_bridge import CertifiedBridge
    return native, CertifiedBridge


def state(b):
    import run_native_bridge as native
    value = json.loads(json.dumps(native.observe(b.runtime, b.profile)))
    if b.profile == 'FCI':
        value['native_control'] = dict(poisoned=b.engine.poisoned, meta=b.engine.meta(),
             phases=list(b.db.execute('SELECT operation_id,phase FROM d2_operations ORDER BY operation_id')))
    else:
        value['native_control'] = dict(control=b.engine.control(), witness=b.engine.witness(),
             phases=list(b.engine.ref.execute('SELECT operation_id,phase FROM attempts ORDER BY operation_id')))
    return value


def child(args):
    native, Bridge = setup(args)
    from handoff import public, signed, verify
    from native_bridge import RESULT
    from recovery import safe_rearm, recovery_gate, RecoveryHeld
    from uds_service import harden
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    identity = harden()
    keys = json.loads((args.runtime / 'bridge-private.json').read_text())
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys['issuer']))
    sink = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys['sink']))
    b = Bridge(args.native_root, args.runtime, args.profile, signer, sink, initialize=args.phase == 'fault')
    row = dict(profile=args.profile, case=args.case, phase=args.phase, identity=identity,
               pid=os.getpid(), B_attempted=False, forbidden_effects=0, legitimate_recovered=0,
               persistent_refusal=False, sources_native_modified=False)
    path = args.work / (args.phase + '.json')
    try:
        if args.phase == 'fault':
            native.need(safe_rearm(b, native.CONTROL)['status'] == 'READY', 'INITIAL_REARM')
            k = dict(scope='verified-service-recovery', deployment=b.deployment,
                     sink=args.profile, operation_id='SAME_BUSINESS_K')
            content = dict(schema='SQL-SET/1', action='set_value', target='synthetic-config', expected_version=0, value=1)
            h = b.bind(k, content, native.CONTROL)
            a = b.assign(k, h, 0, native.A, native.CONTROL)
            request = b.issue(a, native.CONTROL)
            context = dict(key=k, h=h, content=content, request_A=request, sink_public=public(sink), issuer_public=public(signer))
            def fence():
                answer = b.certify_nonexecution(k, h, 1, native.B, native.CONTROL)
                context['certificate'] = answer['certificate']
                context['allocation_B'] = b.redeem(answer['certificate'], native.CONTROL)
            try:
                row['old_A'] = b.execute(request, native.A, after_precheck=fence)
            except b.auth.AuthorizationRefused as exc:
                native.need(str(exc) == 'STALE_ATTEMPT', 'WRONG_A_REFUSAL')
                row['old_A'] = dict(exception='STALE_ATTEMPT')
            native.need(any(x.get('stage') == 'native_admission' and x['in_transaction'] for x in b.guard_observations), 'NO_LATE_GUARD')
            row['after_old_refusal'] = state(b)
            native.need(not row['after_old_refusal']['native_effects'], 'FORBIDDEN_A_EFFECT')
            put(args.work / 'context.json', context)
            row['context'] = context
            if args.case == 'helper_only':
                row['helper'] = safe_rearm(b, native.CONTROL)
                if row['helper']['status'] == 'READY':
                    row['B_attempted'] = True
                    req = b.issue(context['allocation_B'], native.CONTROL)
                    row['request_B'] = req
                    row['response_B'] = b.execute(req, native.B)
                    row['legitimate_recovered'] = int(row['response_B']['status'] == 'NEW')
                else:
                    row['persistent_refusal'] = True
        else:
            context = json.loads((args.work / 'context.json').read_text())
            supervisor = json.loads((args.work / 'supervisor.json').read_text())
            actor = native.A if args.case == 'wrong_actor' else native.CONTROL
            # Explicit injections, performed only in disposable test fixtures.
            if args.phase == 'recover':
                if args.case == 'missing_certificate':
                    b.db.execute('DELETE FROM sk_certificates'); b.db.commit()
                elif args.case == 'authority_revoked':
                    b.revoke(native.CONTROL)
                elif args.case == 'effect_divergence':
                    b.db.execute('UPDATE '+b.table+' SET version=1 WHERE target=?', ('synthetic-config',)); b.db.commit()
            row['before_gate'] = state(b)
            try:
                row['gate'] = recovery_gate(b, context, actor, supervisor)
            except (RecoveryHeld, b.auth.AuthorizationRefused) as exc:
                row['gate'] = dict(status='HOLD', code=str(exc))
                row['persistent_refusal'] = True
            if row['gate']['status'] == 'CONSISTENT_FOR_SUPERVISED_REARM':
                if args.case == 'native_conditions_false':
                    if args.profile == 'FCI': b.engine.conditions = (False, True, True, True, True)
                    else: b.engine.provider = lambda: dict(flags=[False, True, True, True, True], source_ok=True)
                if args.case == 'crash_before_rearm' and args.phase == 'recover':
                    put(path, dict(row, crash='BEFORE_REARM')); os._exit(86)
                try:
                    row['helper'] = safe_rearm(b, actor)
                except b.auth.AuthorizationRefused as exc:
                    row['helper'] = dict(status='HOLD', code=str(exc))
                if args.case == 'crash_after_rearm' and args.phase == 'recover':
                    put(path, dict(row, crash='AFTER_REARM')); os._exit(86)
                if row['helper']['status'] == 'READY':
                    # Check A is still fenced even with new native epochs.
                    try:
                        b.execute(context['request_A'], native.A)
                        raise ValueError('OLD_A_READMITTED')
                    except b.auth.AuthorizationRefused as exc:
                        native.need(str(exc) == 'STALE_ATTEMPT', 'OLD_A_WRONG_REFUSAL')
                        row['old_A_after_rearm'] = str(exc)
                    # Fresh permit, same successor allocation, K and H. This is
                    # ordinary admission; no B call follows a refused gate/helper.
                    req = b.issue(context['allocation_B'], actor)
                    row['request_B'] = req; row['B_attempted'] = True
                    row['response_B'] = b.execute(req, native.B)
                    row['legitimate_recovered'] = int(row['response_B']['status'] == 'NEW')
                    native.need(row['legitimate_recovered'] == 1, 'EXPECTED_NATIVE_B_PROGRESS')
                    result = verify(row['response_B']['result'], public(sink), RESULT)
                    native.need(result['key'] == context['key'] and result['content_hash'] == context['h'] and
                                result['native_operation_id'] == context['allocation_B']['rid'], 'SIGNED_RESULT_BINDING')
                    row['repeat_B'] = b.execute(req, native.B)
                    native.need(row['repeat_B']['status'] == 'RECOVERED' and
                                row['repeat_B']['result'] == row['response_B']['result'], 'IDEMPOTENT_RESULT')
                else: row['persistent_refusal'] = True
        row['final_state'] = state(b)
        effects = row['final_state']['native_effects']
        context = row.get('context') or context
        row['forbidden_effects'] = sum(e[0] != context['allocation_B']['rid'] for e in effects)
        native.need(row['forbidden_effects'] == 0 and len(effects) == row['legitimate_recovered'], 'EFFECT_ACCOUNTING')
        native.need(row['legitimate_recovered'] or row['persistent_refusal'] or args.phase == 'fault', 'UNCLASSIFIED_OUTCOME')
        row['guard_observations'] = b.guard_observations
        put(path, row)
    finally:
        b.close()


def run(args):
    native, _ = setup(args)
    args.out.mkdir(parents=True, exist_ok=False)
    maps = [list(map(int, s.split())) for s in Path('/proc/self/uid_map').read_text().splitlines()]
    if os.geteuid() != 0 or not any(lo <= native.OWNER < lo+n for lo, _, n in maps):
        put(args.out / 'RESULTS.json', dict(status='NOT_RUN_HOST_UIDS_UNAVAILABLE', native_cases=0, uid_map=maps, M1='HOLD'))
        return 3
    manifest = native.checked_sources(args.native_root)
    rows, failures = [], []
    with tempfile.TemporaryDirectory(prefix='verified-recovery-') as tmp:
        parent = Path(tmp); parent.chmod(0o755)
        # Read-only public code closure outside the Actions checkout's ancestors.
        root = parent / 'native'; root.mkdir(mode=0o755)
        for name in manifest['files']:
            p = root / name; p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(args.native_root / name, p); p.chmod(0o444)
        support = parent / 'support' / 'fci-same-k-handoff-20261030'; support.mkdir(parents=True)
        reference = parent / 'reference'; reference.mkdir()
        code = parent / 'code'; code.mkdir()
        for source, dest, names in ((args.support_root / 'fci-same-k-handoff-20261030', support,
                                      ('run_native_bridge.py','native_bridge.py','handoff.py','uds_service.py','NATIVE_SOURCES.json')),
                                    (args.reference_root, reference, ('certified_bridge.py',)),
                                    (HERE, code, ('run_recovery.py','recovery.py'))):
            for name in names: shutil.copyfile(source / name, dest / name); (dest / name).chmod(0o444)
        for p in parent.rglob('*'):
            if p.is_dir(): p.chmod(0o755)
        copied = {str(p.relative_to(parent)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for directory in (root, support, reference, code) for p in directory.rglob('*') if p.is_file()}
        for profile in ('FCI','STANDARD'):
            for case in CASES:
                folder = parent / (profile+'-'+case); folder.mkdir(mode=0o755)
                runtime = native.provision(root, folder, profile)
                work = folder / 'work'; work.mkdir(mode=0o700); os.chown(work,native.OWNER,native.OWNER)
                core = runtime / ('consumer.db' if profile == 'FCI' else 'resource.db')
                inode = core.stat().st_ino
                private_pins = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime.iterdir()
                                if p.is_file() and p.suffix in ('.json','.key')}
                phases = []
                try:
                    for phase in (('fault',) if case == 'helper_only' else
                                  ('fault','recover','resume') if case.startswith('crash_') else ('fault','recover')):
                        cmd = [sys.executable] + (['-O'] if not __debug__ else []) + ['-I','-B',str(code/'run_recovery.py'),
                            '--child','--phase',phase,'--case',case,'--profile',profile,'--runtime',str(runtime),'--work',str(work),
                            '--native-root',str(root),'--support-root',str(support.parent),'--reference-root',str(reference)]
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                                user=native.OWNER,group=native.OWNER,extra_groups=(),umask=0o077)
                        try: stdout, stderr = proc.communicate(timeout=30)
                        except subprocess.TimeoutExpired:
                            proc.kill(); proc.communicate(); raise ValueError('CHILD_TIMEOUT')
                        expected = 86 if phase == 'recover' and case.startswith('crash_') else 0
                        native.need(proc.returncode == expected, 'CHILD_EXIT:'+str(proc.returncode)+':'+stderr[-2200:])
                        observed = json.loads((work / (phase+'.json')).read_text()); phases.append(observed)
                        native.need(core.stat().st_ino == inode, 'AUTHORITY_REPLACED')
                        native.need(private_pins == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime.iterdir()
                                    if p.is_file() and p.suffix in ('.json','.key')}, 'RETAINED_KEY_OR_CONFIG_CHANGED')
                        if phase in ('fault','recover'):
                            # Receipt is made only by this trusted supervisor after wait.
                            put(work/'supervisor.json',dict(old_process_waited=True,old_exit=proc.returncode,
                                old_pid=proc.pid,single_owner_no_clones=True,authority_inode=inode))
                            os.chown(work/'supervisor.json',native.OWNER,native.OWNER); (work/'supervisor.json').chmod(0o600)
                    final = phases[-1]
                    want = int(case in ('supervised_restart','crash_before_rearm','crash_after_rearm') or
                               case == 'helper_only' and profile == 'STANDARD')
                    native.need(final['legitimate_recovered'] == want and
                                final['persistent_refusal'] == (not bool(want)), 'CASE_OUTCOME')
                    root_readback = json.loads(json.dumps(native.observe(runtime,profile)))
                    native.need(root_readback == {k:v for k,v in final['final_state'].items() if k != 'native_control'}, 'ROOT_SQL_DIFFERS')
                    rows.append(dict(profile=profile,case=case,phases=phases,root_readback=root_readback,
                                     forbidden_effects=final['forbidden_effects'],legitimate_recovered=final['legitimate_recovered'],
                                     persistent_refusal=final['persistent_refusal'],authority_inode_retained=True))
                    print(profile,case,'PASS',flush=True)
                except Exception:
                    failures.append(dict(profile=profile,case=case,phases=phases,error=traceback.format_exc()))
                    print(profile,case,'FAIL',failures[-1]['error'][-1600:],flush=True)
                finally:
                    shutil.rmtree(folder)
        native.checked_sources(root); native.checked_sources(args.native_root)
        native.need(copied == {str(p.relative_to(parent)):hashlib.sha256(p.read_bytes()).hexdigest()
                    for directory in (root,support,reference,code) for p in directory.rglob('*') if p.is_file()}, 'SOURCES_CHANGED')
    report = dict(status='PASS_SCOPED' if not failures else 'FAIL',cases=len(rows),expected_cases=18,
                  failures=len(failures),optimized=not __debug__,native_sources=manifest,
                  copied_sources=copied,source_hashes={n:hashlib.sha256((HERE/n).read_bytes()).hexdigest()
                    for n in ('run_recovery.py','recovery.py')},
                  forbidden_effects=sum(r['forbidden_effects'] for r in rows),
                  legitimate_recovered=sum(r['legitimate_recovered'] for r in rows),
                  persistent_refusals=sum(r['persistent_refusal'] for r in rows),
                  native_engines_modified=False,direct_flag_reset=False,hot_recovery_qualified=False,
                  independent_audit=False,rollback_resistance=False,comparative_advantage=False,M1='HOLD')
    for name,obj in (('RESULTS.json',report),('EVIDENCE.json',rows),('FAILURES.json',failures)): put(args.out/name,obj)
    return int(bool(failures))


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    for name in ('support-root','reference-root','native-root','out','runtime','work'):p.add_argument('--'+name,type=Path)
    p.add_argument('--child',action='store_true');p.add_argument('--phase');p.add_argument('--profile');p.add_argument('--case')
    a=p.parse_args()
    if a.child: child(a)
    else: sys.exit(run(a))
