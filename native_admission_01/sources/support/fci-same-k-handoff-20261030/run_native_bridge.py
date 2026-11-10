"""Disposable native SQL adapter checks. Root provisions; owner UID executes.

The A/B UID arguments inside the owner process are trusted test inputs. This
lot does NOT connect the native engines to the multi-UID RPC transport.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parent))
from native_bridge import NativeBridge, load_native, provision_ledger, PERMIT
from handoff import canonical, public, signed
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption

OWNER,CONTROL,A,B=62021,62022,62023,62024
CASES=('nominal_A','transfer_B','A_wins_read_B','content_conflict','wrong_UID',
       'direct_native_blocked','altered_native_binding','abort_before_commit',
       'crash_before_commit','crash_after_commit','expiry_after_lock',
       'revoke_after_precheck','native_conditions_refuse','native_expiry_refuse',
       'native_precondition_refuse','old_continuation_under_guard','restart_history')
POSITIVE={'nominal_A','transfer_B','A_wins_read_B','crash_after_commit','restart_history'}


def need(ok,reason):
    if not ok:raise ValueError(reason)


def checked_sources(root):
    manifest=json.loads((Path(__file__).parent/'NATIVE_SOURCES.json').read_text())
    for name,wanted in manifest['files'].items():
        need(hashlib.sha256((root/name).read_bytes()).hexdigest()==wanted,'FROZEN_SOURCE_HASH:'+name)
    return manifest


def native_rearm(bridge):
    s=bridge.engine
    if bridge.profile=='FCI':
        from fci_hardened.service import clock
        from base01.authority import State,fixture_witness
        from lifecycle import Local,fixture_rearm
        keys={k:bytes.fromhex(v) for k,v in json.loads((bridge.runtime/'keys.json').read_text()).items()}
        view=s.handle(CONTROL,canonical(dict(op='rearm_state')))
        if view['authority']['mask']:
            w=fixture_witness(State(**view['authority']),keys['rearm'],clock())
            r=s.handle(CONTROL,canonical(dict(op='rearm_authority',witness=w)))
            need(r['code']=='REARM_ACCEPTED','NATIVE_AUTHORITY_REARM:'+str(r))
        view=s.handle(CONTROL,canonical(dict(op='rearm_state')))
        if view['consumer']['mask']:
            w=fixture_rearm(Local(**view['consumer']),keys['local_rearm'],clock())
            r=s.handle(CONTROL,canonical(dict(op='rearm_local',witness=w)))
            need(r['code']=='REARM_LOCAL_ACCEPTED','NATIVE_CONSUMER_REARM:'+str(r))
        need(s.authority_status()=='READY','NATIVE_NOT_READY')
    else:
        s.rearm(s.witness(),list(s.witness()['causes']))


def provision(root,parent,profile):
    load_native(root)
    signer=Ed25519PrivateKey.generate();sink=Ed25519PrivateKey.generate()
    deploy=str(uuid.uuid4());boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if profile=='FCI':
        from fci_hardened.fixture_setup import provision as base_provision
        runtime,_,_=base_provision(parent/'fixture',OWNER,A,CONTROL)
        (runtime/'d2a-public.json').write_text(json.dumps(dict(public_key=public(signer))))
        (runtime/'native-journal.jsonl').touch()
        with sqlite3.connect(runtime/'consumer.db') as db:
            db.executescript('''
              CREATE TABLE demo_configuration(target TEXT PRIMARY KEY,version INTEGER NOT NULL,value INTEGER NOT NULL);
              INSERT INTO demo_configuration VALUES('synthetic-config',0,0),('synthetic-config-decoy',0,0);
              CREATE TABLE demo_effects(event_id INTEGER PRIMARY KEY,operation_id TEXT NOT NULL,target TEXT NOT NULL,old_version INTEGER NOT NULL,new_version INTEGER NOT NULL,value INTEGER NOT NULL,authorization_digest TEXT,ticket_digest TEXT);
              CREATE TABLE d2_operations(operation_id TEXT PRIMARY KEY,envelope TEXT NOT NULL,authorization_digest TEXT NOT NULL,uid INTEGER NOT NULL,ticket_digest TEXT,phase TEXT NOT NULL);
              CREATE TABLE d2_meta(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL,recovery INTEGER NOT NULL,deployment_id TEXT NOT NULL,boot_id TEXT NOT NULL);
            ''')
            db.execute('INSERT INTO d2_meta VALUES(1,0,0,?,?)',(deploy,boot));db.commit()
            from fci_hardened.policy import verify_policy
            policy=verify_policy((runtime/'policy.json').read_bytes(),(runtime/'policy-public.key').read_bytes()).digest
            provision_ledger(db,policy)
    else:
        from setup_fixture import provision as std_provision
        from fci_hardened.service import CONTEXT
        runtime=parent/'state'
        std_provision(runtime,dict(public_key=public(signer),deployment_id=deploy,boot_id=boot,policy_digest='a'*64,context=CONTEXT,requester_uid=A,maintainer_uid=CONTROL))
        with sqlite3.connect(runtime/'resource.db') as db:provision_ledger(db,'a'*64)
    keys={name:key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()).hex() for name,key in (('issuer',signer),('sink',sink))}
    (runtime/'bridge-private.json').write_text(json.dumps(keys))
    for p in runtime.iterdir():
        if p.is_file():p.chmod(0o600);os.chown(p,OWNER,OWNER)
    os.chown(runtime,OWNER,OWNER)
    return runtime


def child(root,runtime,profile,case):
    keys=json.loads((runtime/'bridge-private.json').read_text())
    signer=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys['issuer']))
    sink=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys['sink']))
    tick=[1000]
    b=NativeBridge(root,runtime,profile,signer,sink,now=lambda:tick[0])
    native_rearm(b)
    k=dict(scope='same-k-native-lab',deployment=b.deployment,sink=profile,operation_id='BUSINESS_K')
    c=dict(schema='SQL-SET/1',action='set_value',target='synthetic-config',expected_version=0,value=1)
    h=b.bind(k,c,CONTROL);alloc=b.assign(k,h,0,A,CONTROL);request=b.issue(alloc,CONTROL)
    evidence=dict(case=case,profile=profile,key=k,content=c,request_A=request)
    def expect_refusal(fn,code):
        try:r=fn()
        except Exception as e:
            need(code in str(e),'WRONG_REFUSAL:'+str(e));return str(e)
        raise ValueError('EXPECTED_REFUSAL:'+str(r))
    def invoke(req=request,uid=A,**kw):
        try:return b.execute(req,uid,**kw)
        except b.auth.AuthorizationRefused as e:return dict(status='NATIVE_EXCEPTION_HOLD',error=str(e))
    try:
        if case=='nominal_A':
            evidence['response']=invoke();need(evidence['response']['status']=='NEW','NOMINAL')
        elif case=='transfer_B':
            evidence['resolution']=b.resolve(k,h,1,CONTROL)
            ab=b.assign(k,h,1,B,CONTROL);pb=b.issue(ab,CONTROL)
            evidence['request_B']=pb
            evidence['old_A']=expect_refusal(lambda:b.execute(request,A),'STALE_ATTEMPT')
            evidence['response']=invoke(pb,B);need(evidence['response']['status']=='NEW','TRANSFER')
        elif case=='A_wins_read_B':
            first=invoke();need(first['status']=='NEW','A_FIRST')
            evidence['resolution']=b.resolve(k,h,1,CONTROL)
            expect_refusal(lambda:b.assign(k,h,1,B,CONTROL),'RESULT_ALREADY_COMMITTED')
            expect_refusal(lambda:b.read_result(k,h,B),'READ_ROLE')
            b.grant_read(k,h,B,CONTROL)
            evidence['response']=dict(status='READ',result=b.read_result(k,h,B))
            need(evidence['response']['result']==first['result'],'SAME_RESULT')
        elif case=='content_conflict':
            evidence['refusal']=expect_refusal(lambda:b.bind(k,dict(c,value=0),CONTROL),'CONTENT_CONFLICT')
        elif case=='wrong_UID':
            evidence['refusal']=expect_refusal(lambda:b.execute(request,B),'BRIDGE_SUBJECT')
        elif case=='direct_native_blocked':
            evidence['refusal']=expect_refusal(lambda:b.engine.execute(A,request['native']),'BRIDGE_CONTEXT_REQUIRED')
        elif case=='altered_native_binding':
            bad=copy.deepcopy(request);bad['native']['operation']['value']=0
            evidence['refusal']=expect_refusal(lambda:b.execute(bad,A),'NATIVE_DIGEST')
        elif case in ('abort_before_commit','crash_before_commit','crash_after_commit'):
            def fault(stage):
                if stage==('after_commit' if case=='crash_after_commit' else 'before_commit'):
                    if case.startswith('crash_'):os._exit(86)
                    raise b.auth.AuthorizationRefused('INJECTED_ABORT')
            b.fault=fault;evidence['response']=invoke()
            need(evidence['response']['status']!='NEW','ABORT_PUBLISHED')
        elif case=='expiry_after_lock':
            # Real write-lock wait; deterministic trusted test clock, not wall TTL.
            started=threading.Event();release=threading.Event()
            def holder():
                with sqlite3.connect(b.path,isolation_level=None) as db:
                    db.execute('BEGIN IMMEDIATE');started.set()
                    release.wait(3);tick[0]=1030;db.rollback()
            def arrange():
                t=threading.Thread(target=holder);t.start();need(started.wait(2),'LOCK_HOLDER')
                threading.Timer(0.1,release.set).start()
            evidence['response']=invoke(after_precheck=arrange)
            need(evidence['response']['status']!='NEW','EXPIRED_MUTATION')
            need(any(x['in_transaction'] and x['now']==1030 for x in b.guard_observations),'NO_LATE_TIME_CHECK')
        elif case=='revoke_after_precheck':
            evidence['response']=invoke(after_precheck=lambda:b.revoke(CONTROL))
            need(evidence['response']['status']!='NEW','REVOKED_MUTATION')
        elif case=='native_conditions_refuse':
            if profile=='FCI':b.engine.conditions=(False,True,True,True,True)
            else:b.engine.provider=lambda:dict(flags=[False,True,True,True,True],source_ok=True)
            evidence['response']=invoke();need(evidence['response']['status']!='NEW','NATIVE_CONDITIONS_BYPASSED')
        elif case=='native_expiry_refuse':
            bad=copy.deepcopy(request);nb=bad['native']['authorization']['body'];now=int(time.monotonic())
            nb['not_before']=now-2;nb['not_after']=now-1
            bad['native']['authorization']=signed(signer,b.auth.DOMAIN,nb)
            body=bad['permit']['body'];body['native_digest']=hashlib.sha256(canonical(bad['native'])).hexdigest()
            bad['permit']=signed(sink,PERMIT,body)
            evidence['response']=invoke(bad);need(evidence['response']['status']!='NEW','NATIVE_EXPIRY_BYPASSED')
        elif case=='native_precondition_refuse':
            b.db.execute('UPDATE '+b.table+' SET version=1');b.db.commit()
            evidence['response']=invoke();need(evidence['response']['status']!='NEW','NATIVE_VERSION_BYPASSED')
        elif case=='old_continuation_under_guard':
            b.resolve(k,h,1,CONTROL);b.assign(k,h,1,B,CONTROL)
            # Resume saved request inside trusted native owner; bypass only early
            # bridge precheck to demand an actual refusal at the native SQL hook.
            b.active=(request,A)
            try:
                try:r=b.engine.execute(A,request['native'])
                except Exception as e:r=dict(error=str(e))
            finally:b.active=None
            evidence['response']=r
            need(any(x.get('stage')=='native_admission' and x['in_transaction'] for x in b.guard_observations),'LATE_GUARD_NOT_REACHED')
        elif case=='restart_history':
            first=invoke();need(first['status']=='NEW','FIRST')
            b.close();b=NativeBridge(root,runtime,profile,signer,sink,now=lambda:tick[0])
            result=b.read_result(k,h,A);need(result==first['result'],'RESTART_RESULT')
            evidence['response']=dict(status='READ_AFTER_RESTART',result=result)
        else:raise ValueError('UNKNOWN_CASE')
        evidence['guard_observations']=b.guard_observations
        evidence['owner_uid']=os.geteuid()
        print(json.dumps(evidence),flush=True)
    finally:b.close()


def observe(runtime,profile):
    path=runtime/('consumer.db' if profile=='FCI' else 'resource.db')
    table='demo_configuration' if profile=='FCI' else 'configuration';effects='demo_effects' if profile=='FCI' else 'effects'
    with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True) as db:
        result=db.execute('SELECT result FROM sk_business').fetchall()
        return dict(native_effects=db.execute('SELECT operation_id,old_version,new_version,value FROM '+effects+' ORDER BY operation_id').fetchall(),business_results=[json.loads(r[0]) for r in result if r[0]],business_rows=len(result),attempts=db.execute('SELECT g,uid,rid,state FROM sk_attempts ORDER BY g').fetchall(),configuration=db.execute('SELECT target,version,value FROM '+table+' ORDER BY target').fetchall())


def run(root,out):
    p=Path(out);p.mkdir(parents=True,exist_ok=False)
    maps=[list(map(int,line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
    if os.geteuid()!=0 or not any(lo<=OWNER<lo+n for lo,_,n in maps):
        status=dict(status='NOT_RUN_HOST_UIDS_UNAVAILABLE',cases=0,uid_map=maps)
        (p/'RESULTS.json').write_text(json.dumps(status,indent=2)+'\n');print(json.dumps(status));return 3
    manifest=checked_sources(root);original_root=root;rows=[];failures=[]
    # The Actions checkout's ancestors may deny traversal to the dedicated UID.
    # Export only the attested closure to a root-owned, readable temporary tree.
    source_temp=Path(tempfile.mkdtemp(prefix='sk03-sources-'));source_temp.chmod(0o755)
    root=source_temp/'native';root.mkdir(mode=0o755)
    for name in manifest['files']:
        target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(original_root/name,target);target.chmod(0o444)
    for directory in root.rglob('*'):
        if directory.is_dir():directory.chmod(0o755)
    checked_sources(root)
    code=source_temp/'code';code.mkdir(mode=0o755)
    for name in ('run_native_bridge.py','native_bridge.py','handoff.py','NATIVE_SOURCES.json'):
        shutil.copyfile(Path(__file__).parent/name,code/name);(code/name).chmod(0o444)
    for profile in ('FCI','STANDARD'):
        for case in CASES:
            temp=Path(tempfile.mkdtemp(prefix='sk03-'));temp.chmod(0o755)
            try:
                runtime=provision(root,temp,profile)
                cmd=[sys.executable]+(['-O'] if not __debug__ else [])+['-I','-B',str(code/'run_native_bridge.py'),'--native-root',str(root),'--child-runtime',str(runtime),'--profile',profile,'--case',case]
                r=subprocess.run(cmd,capture_output=True,text=True,user=OWNER,group=OWNER,extra_groups=(),umask=0o077,timeout=20)
                expected=86 if case.startswith('crash_') else 0
                need(r.returncode==expected,'CHILD_EXIT:'+str(r.returncode)+':'+r.stderr[-2500:])
                evidence=json.loads(r.stdout) if r.stdout.strip() else dict(case=case,profile=profile,owner_uid=OWNER)
                state=observe(runtime,profile);count=1 if case in POSITIVE else 0
                need(len(state['native_effects'])==len(state['business_results'])==count,'ATOMIC_READBACK:'+str(state))
                need(state['business_rows']==1,'BUSINESS_K_MISSING')
                if count:
                    result=state['business_results'][0]['body'];effect=state['native_effects'][0]
                    need((result['native_operation_id'],result['old_version'],result['new_version'],result['value'])==tuple(effect),'NATIVE_RESULT_BINDING')
                rows.append(dict(profile=profile,case=case,exitcode=r.returncode,evidence=evidence,readback=state))
                print(profile,case,'PASS',flush=True)
            except Exception:
                failures.append(dict(profile=profile,case=case,error=traceback.format_exc()));print(profile,case,'FAIL',failures[-1]['error'][-1800:],flush=True)
            finally:shutil.rmtree(temp)
    checked_sources(root);checked_sources(original_root);shutil.rmtree(source_temp)
    summary=dict(schema='SAME-K-NATIVE-BRIDGE-REPORT/1',status='PASS_SCOPED' if not failures else 'FAIL',cases=len(rows),expected_cases=34,distinct_scenarios_per_profile=17,failures=len(failures),optimized=not __debug__,source_commit=manifest['commit'],source_files=len(manifest['files']),owner_uid=OWNER,native_engines_executed=bool(rows),native_rpc_bridge=False,full_no_bypass=False,physical=False,common_new_adapter=True,comparative_advantage=False,rollback_resistance=False,M1='HOLD')
    (p/'RESULTS.json').write_text(json.dumps(summary,indent=2)+'\n')
    (p/'PUBLIC_EVIDENCE.json').write_text(json.dumps(rows,indent=2)+'\n')
    (p/'FAILURES.json').write_text(json.dumps(failures,indent=2)+'\n')
    print(json.dumps(summary));return int(bool(failures))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--native-root',type=Path,required=True);parser.add_argument('--out');parser.add_argument('--child-runtime',type=Path);parser.add_argument('--profile');parser.add_argument('--case');a=parser.parse_args()
    if a.child_runtime:child(a.native_root.resolve(),a.child_runtime,a.profile,a.case)
    else:sys.exit(run(a.native_root.resolve(),a.out))
