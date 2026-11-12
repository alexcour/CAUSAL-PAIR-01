"""Independent offline oracle: signatures, actual SQL deltas, kernel peers and cuts.

No execution/native/activation implementation imported. Native MAC evidence is
produced in the trusted owner, not independently revalidated from fixture secrets.
"""
import argparse,copy,hashlib,importlib.util,json,sys
from pathlib import Path
from types import SimpleNamespace
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE.parent/'crash'))
import quiescence as q
GRANT=b'FCI-C-NATIVE-TRANSITION-GRANT/1\0';PERMIT=b'FCI-C-NATIVE-CONSUMABLE-PERMIT/1\0';RPC=b'FCI-C-NATIVE-EXECUTION-RPC/1\0'
CASES=('success','before_commit','after_commit','expired_after_precheck','revoked_after_precheck','expired_before_commit','expired_before_commit_kill')
def load(p):return json.loads(p.read_text())
def peer(c,uid):
    q.need(c['client_uid']==uid and c['response']['peer']==dict(pid=c['client_pid'],uid=uid,gid=uid),'C_KERNEL_PEER');return c['response']
def result(c,uid,op,pin,policy):
    w=peer(c,uid);q.need(w['ok'] is True,'C_RPC_SUCCESS:'+op+':observed='+json.dumps(w,sort_keys=True));v=w['result'];b=q.verify(v['receipt'],pin,RPC)
    q.need(b==dict(schema='FCI-C-NATIVE-EXECUTION-RPC/1',op=op,uid=uid,result_digest=q.digest(v['result']),execution_policy=policy),'C_RPC_SIGNATURE_AND_BINDING');return v['result']
def denied(c,uid,code=None):
    w=peer(c,uid);q.need(w['ok'] is False and type(w['error']) is str and (code is None or w['error']==code),'C_EXACT_REFUSAL:'+str(code)+':observed='+json.dumps(w,sort_keys=True))
def one(r,sources):
    x=r['execution'];profile=r['profile'];main=q.authority_names(profile)[0];pin=r['trust_anchors']['sink'];policy=sources['files']['execution/execution.py'];case=r['execution_case']
    q.need(r['status']=='CAPTURED' and case in CASES and x['before']['stores']==r['admission_final']['stores'],'C_PHASE_BOUNDARY')
    if r['cut']=='after_commit':
        denied(x['activate'],62022,'ADMITTED_C_REQUIRED');q.need(x['before']['stores']==x['final']['stores'],'C_HISTORICAL_NO_STATE_CHANGE')
        q.need('native_ready' not in x,'HISTORICAL_MUST_NOT_START_C');return dict(profile=profile,case=case,historical=True,C_effect=False)
    active=x['activate']['response'];q.need(peer(x['activate'],62022)['ok'] is True,'C_ACTIVATED')
    cert=active['result']['result']['certificate'];cb=q.verify(cert,pin,b'FCI-C-ACTIVATION/1\0');allocation=cb['allocation'];rid=allocation['rid']
    q.need(cb['activation_policy']==sources['files']['activation/activation.py'] and allocation['uid']==62026 and allocation['generation']==3,'C_ACTIVATION_BINDING')
    get=lambda name,uid,op:result(x[name],uid,op,pin,policy)
    grants={}
    for name,purpose in [('start_grant','STARTUP'),('rearm_grant','REARM'),('execute_grant','EXECUTE')]+([('resume_start_grant','STARTUP')] if case in ('before_commit','after_commit','expired_before_commit_kill') else []):
        item=x[name];g=q.verify(item['grant'],r['supervisor_public'],GRANT);grants[name]=g
        q.need(g['schema']=='FCI-C-NATIVE-TRANSITION-GRANT/1' and g['purpose']==purpose and g['execution_policy']==policy and g['activation']==cert
            and g['scope']==dict(key=allocation['key'],h=allocation['h']) and g['state_digest']==q.digest(item['snapshot']['stores'])
            and type(g['not_before']) is type(g['not_after']) is int and g['not_after']==g['not_before']+120
            and g['boot_id']==r['pidfd_birth']['boot_id'],'ROOT_C_TRANSITION_GRANT')
        q.need(item['boundary']==dict(uid=0,mode=0o444,parent_uid=0,parent_mode=0o755),'ROOT_C_TRANSITION_BOUNDARY')
    q.need(grants['start_grant']['state_digest']==q.digest(x['activated']['stores']) and grants['start_grant']['owner_wait']==x['activation_wait'],'C_START_AFTER_ACTIVATION_WAIT')
    q.need(grants['rearm_grant']['state_digest']==q.digest(x['after_startup']['stores']) and grants['execute_grant']['state_digest']==q.digest(x['after_rearm']['stores']),'C_DISTINCT_STARTUP_REARM_EPOCH')
    for name in ['native_ready']+(['resume_ready'] if case in ('before_commit','after_commit','expired_before_commit_kill') else []):
        ready=x[name];i=ready['identity'];q.need(ready['normal_native_constructor_called'] is True and ready['sink_public']==pin
            and i['uid']==i['euid']==62021 and i['dumpable']==0 and i['no_new_privs']=='1' and int(i['cap_eff'],16)==0,'NORMAL_HARDENED_C_OWNER')
        q.need(ready['role_C_native'] is True if profile=='FCI' else ready['role_C_native']=='SIGNED_STANDARD_UID_AND_VERSIONED_FACADE','EXPLICIT_C_ROLE_EXTENSION')
    q.need(get('rearm',62022,'rearm_C')['status']=='READY','NORMAL_REARM_READY');denied(x['rearm_wrong_role'],62026,'CONTROL_ROLE');denied(x['issue_wrong_role'],62026,'CONTROL_ROLE')
    issue=get('issue',62022,'issue_C');p=q.verify(issue['permit'],pin,PERMIT);request=issue['request'];bp=q.verify(request['permit'],pin,b'SAME-K-NATIVE-BRIDGE-PERMIT/1\0');na=q.verify(request['native']['authorization'],r['trust_anchors']['issuer'],b'FCI-SQL-D2A-AUTHZ/1\0')
    q.need(p==dict(schema='FCI-C-NATIVE-CONSUMABLE-PERMIT/1',challenge='c'*32,request_digest=q.digest(request),grant_digest=q.digest(x['execute_grant']['grant']),activation_digest=q.digest(cert),allocation=allocation,
        execution_policy=policy,owner_pid=x['native_ready']['pid'],native_epoch=grants['execute_grant']['native_epoch'],boot_id=grants['execute_grant']['boot_id'],not_before=bp['not_before'],not_after=bp['not_after']),'EXACT_FRESH_C_PERMIT')
    q.need(na['subject_uid']==bp['subject_uid']==62026 and na['operation_id']==bp['native_operation_id']==rid and na['authority_epoch']==p['native_epoch']
        and bp['generation']==3 and bp['attempt_id']==allocation['attempt_id'] and bp['key']==allocation['key'] and bp['content_hash']==allocation['h']
        and bp['native_digest']==q.digest(request['native']) and p['not_after']==p['not_before']+(5 if case=='expired_after_precheck' or case.startswith('expired_before_commit') else 25),'NATIVE_C_SIGNATURES_AND_EPOCH')
    for k,v in request['native']['operation'].items():q.need(na[k]==v,'NATIVE_C_OPERATION_BINDING')
    for call,uid in zip(x['execute_wrong_roles'],(62022,62023,62024,62025)):denied(call,uid,'UNKNOWN_UID' if uid==62025 else 'C_ROLE')
    probes=x['negative_probes']
    codes=dict(bad_signature='SIGNATURE_INVALID',bad_signature_bit='SIGNATURE_INVALID',bad_signed_binding='C_PERMIT_BINDING',
        bad_request='C_PERMIT_BINDING',bad_signer='SIGNATURE_INVALID',bad_domain='SIGNATURE_INVALID')
    q.need(set(probes)==set(codes),'EXACT_NEGATIVE_PROBES')
    for name,code in codes.items():
        denied(x[name],62026,code);probe=probes[name];bad=probe['request']
        q.need(probe['before']['stores']==probe['after']['stores'],'PROBE_NO_STORE_CHANGE:'+name)
        before_count=result(probe['before_count'],62026,'diagnostics_C',pin,policy)
        after_count=result(probe['after_count'],62026,'diagnostics_C',pin,policy)
        q.need(before_count['execute_entry_calls']==after_count['execute_entry_calls']==0,'NEGATIVE_NO_NATIVE_ENTRY:'+name)
        expected_bad=copy.deepcopy(issue)
        if name in ('bad_signature','bad_signed_binding'):expected_bad['permit']['body']['allocation']['uid']=62024
        elif name=='bad_request':expected_bad['request']['native']['operation']['value']+=1
        if name=='bad_signature_bit':
            sig=bytearray.fromhex(expected_bad['permit']['signature']);sig[0]^=1;expected_bad['permit']['signature']=sig.hex()
        if name in ('bad_signed_binding','bad_signer','bad_domain'):expected_bad['permit']['signature']=bad['permit']['signature']
        q.need(bad==expected_bad,'EXACT_NEGATIVE_WITNESS:'+name)
        if name=='bad_signed_binding':q.verify(bad['permit'],pin,PERMIT)
        elif name!='bad_request':
            try:q.verify(bad['permit'],pin,PERMIT)
            except Exception:pass
            else:raise ValueError('NEGATIVE_SIGNATURE_VALID:'+name)
    if case.startswith('expired_before_commit'):
        marker=x['temporal_marker']
        q.need(marker['pid']==x['native_ready']['pid'] and marker['uid']==62021 and marker['point']=='before_commit'
            and marker['deadline']==p['not_after'] and marker['tick']<p['not_after']<=x['temporal_release_tick'],'TEMPORAL_AFTER_FINAL_SAMPLE')
    expected=copy.deepcopy(x['after_rearm']['stores']);expected[main]['c_execution_permits']['rows']=[['c'*32,q.canonical(issue['permit']).decode(),q.canonical(request).decode()]]
    q.need(x['before_effect']['stores']==expected,'PERMIT_ISSUANCE_ONLY_BEFORE_EFFECT')
    if case in ('before_commit','after_commit','expired_before_commit_kill'):
        q.need(x['native_wait']==dict(pid=x['native_ready']['pid'],exit=-9,waited=True,pidfd_bound=True) and x['kill_marker']==dict(pid=x['native_ready']['pid'],uid=62021,point=('before_commit' if case=='expired_before_commit_kill' else case),**({k:x['temporal_marker'][k] for k in ('tick','deadline')} if case=='expired_before_commit_kill' else {})),'REAL_C_CUT_AND_WAIT')
        q.need(x['lost_reply']['client_uid']==62026 and x['lost_reply']['error']=='NATIVE_EOF_NO_ACK' and x['lost_reply']['exit']!=0,'C_RESPONSE_WAS_LOST')
        q.need(grants['resume_start_grant']['owner_wait']==x['native_wait'] and grants['resume_start_grant']['state_digest']==q.digest(x['after_effect']['stores']),'ROOT_RESUME_WAITS_FOR_C_OWNER')
        denied(x['resume_old_permit'],62026,'EXECUTION_OWNER_OR_SCOPE')
        q.need(x['resume_before']['stores']==x['resume_after']['stores'],'RESUME_OLD_PERMIT_AND_HISTORY_WRITE_NOTHING')
        q.need(x['resume_wait']==dict(pid=x['resume_ready']['pid'],exit=-15,waited=True),'C_RESUME_OWNER_WAIT')
    else:q.need(x['native_wait']==dict(pid=x['native_ready']['pid'],exit=-15,waited=True),'C_OWNER_WAIT')
    has_effect=case in ('success','after_commit','expired_before_commit');stores=x['after_effect']['stores'];effects=q.rows(stores,main,'demo_effects' if profile=='FCI' else 'effects');cons=q.rows(stores,main,'c_permit_consumptions')
    q.need(len(effects)==len(cons)==int(has_effect),'ATOMIC_NATIVE_EFFECT_AND_CONSUMPTION')
    q.need(all(e['operation_id']==rid for e in effects),'NO_OLD_A_OR_B_EFFECT')
    business=q.rows(stores,main,'sk_business')[0];attempts=q.rows(stores,main,'sk_attempts');c=next(z for z in attempts if z['rid']==rid)
    q.need(len(attempts)==3 and all(z['state']=='FENCED' for z in attempts if z['rid']!=rid),'PREDECESSORS_STAY_FENCED')
    if case in ('expired_after_precheck','revoked_after_precheck'):
        diagnostic=get('post_execute_diagnostics',62026,'diagnostics_C')
        q.need(diagnostic['execute_entry_calls']==1 and diagnostic['check_failures'],'AFTER_PRECHECK_ENTERED_NATIVE')
        last=diagnostic['check_failures'][-1]
        q.need(last['stage'] in ('admit','finish') and last['in_native_transaction'] is True
            and last['code']==('C_PERMIT_EXPIRED' if case=='expired_after_precheck' else 'C_REVOKED'),'REFUSAL_REACHED_NATIVE_TRANSACTION')
    history=get('history',62026,'history_C');again=get('history_repeat',62026,'history_C');q.need(history==again,'IDENTICAL_C_HISTORY')
    if has_effect:
        value=json.loads(business['result']);result_body=q.verify(value,pin,b'SAME-K-NATIVE-BRIDGE-RESULT/1\0');record=cons[0]
        q.need(record==dict(challenge='c'*32,permit_digest=q.digest(issue['permit']),rid=rid,result_digest=q.digest(value),checked_tick=record['checked_tick'])
            and p['not_before']<=record['checked_tick']<p['not_after'],'CONSUMPTION_SIGNATURE_RESULT_AND_TIME')
        q.need(c['state']=='APPLIED' and result_body['generation']==3 and result_body['subject_uid']==62026 and result_body['native_operation_id']==rid and result_body['key']==allocation['key'] and result_body['content_hash']==allocation['h'],'SIGNED_C_BUSINESS_RESULT')
        q.need(history['status']=='C_RESULT_RETRIEVED' and history['result']==value and history['native']['effect_status']=='COMMITTED_PROVEN' and history['new_effect'] is False,'NATIVE_C_HISTORY_WITHOUT_REEXECUTION')
        q.need(effects[0]['old_version']==result_body['old_version']==0 and effects[0]['new_version']==result_body['new_version']==1 and effects[0]['value']==result_body['value']==1,'ONE_C_SQL_UPDATE')
        if case in ('success','expired_before_commit'):
            executed=get('execute',62026,'execute_C')
            q.need(executed['response']['status']=='NEW' and executed['response']['native']['new_effect'] is True,'NORMAL_NATIVE_C_NEW_RESULT')
            if case=='success':
                repeated=get('repeat_execute',62026,'execute_C')
                q.need(repeated['response']['status']=='RECOVERED' and repeated['response']['result']==value,'IDEMPOTENT_C_RESULT')
            q.need(len(executed['final_checks'])==1 and executed['final_checks'][0]==dict(in_native_transaction=True,tick=record['checked_tick'],deadline=p['not_after'],permit_digest=q.digest(issue['permit'])),'FINAL_CHECK_IN_NATIVE_TXN')
    else:
        q.need(business['result'] is None and history==dict(status='HOLD_NO_C_RESULT',execution_authorized=False),'NO_RESULT_IS_NOT_RETRY_PERMISSION')
        if case=='expired_after_precheck':denied(x['execute'],62026,'C_PERMIT_EXPIRED')
        elif case=='revoked_after_precheck':denied(x['execute'],62026,'C_REVOKED')
        q.need(c['state']==('FENCED' if case=='revoked_after_precheck' else 'OPEN'),'C_NOT_APPLIED_ON_HOLD')
    # B reservation is retained even when normal rearm quarantines its native phase.
    bid=r['writer_ready']['request_B']['permit']['body']['native_operation_id']
    if profile=='FCI':
        getspend=lambda s:json.loads(bytes.fromhex(q.rows(s,'spend.db','ledger')[0]['payload']['bytes_hex']))['attempts'][bid]
        q.need(getspend(x['before']['stores'])==getspend(x['final']['stores']),'B_SPEND_RESERVATION_RETAINED')
    else:
        getb=lambda s:next(z for z in q.rows(s,'reference.db','attempts') if z['operation_id']==bid)
        q.need(getb(x['before']['stores'])==getb(x['final']['stores']),'B_STANDARD_RESERVATION_RETAINED')
    for table in ('native_retirements','native_retirement_events','native_admissions','native_admission_events','c_activations','c_permits','c_activation_events','sk_certificates','sk_certificate_events','producer_results'):
        if case=='revoked_after_precheck' and table=='c_activations':continue
        q.need(x['activated']['stores'][main][table]==x['final']['stores'][main][table],'RETAINED_PROVENANCE:'+table)
    inv=grants['start_grant']['inventory'];end=x['final_inventory'];q.need(set(inv)==set(end),'RETAINED_ALL_NATIVE_AUTHORITIES')
    for n,v in inv.items():q.need({k:z for k,z in v.items() if k!='sha256'}=={k:z for k,z in end[n].items() if k!='sha256'},'RETAINED_NATIVE_AUTHORITY_IDENTITY')
    return dict(profile=profile,case=case,historical=False,C_effect=has_effect)
def run(a):
    raw=a.manifest.read_bytes();q.need(hashlib.sha256(raw).hexdigest()==a.manifest_sha256,'CAPTURE_MANIFEST_HASH');m=load(a.manifest);sources=load(a.source_manifest)
    q.need(m['sources']==sources and m['source_manifest_sha256']==hashlib.sha256(a.source_manifest.read_bytes()).hexdigest(),'EXECUTION_SOURCE_BINDING')
    q.need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==sources['files']['execution/receive.py'],'EXECUTION_RECEIVER_SOURCE')
    # Receive each original eight-cell parent group with the frozen admission1.1 reader.
    spec=importlib.util.spec_from_file_location('prior_admission_reader',HERE.parent/'admission/receive.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    q.need(len(m['cells'])==56,'FIFTY_SIX_CAPTURE_CELLS')
    for case in CASES:
        sub=dict(m,cells=[x for x in m['cells'] if x['execution_case']==case]);path=a.manifest.with_name('parent-'+case+'.json');data=(json.dumps(sub,sort_keys=True,indent=2)+'\n').encode();path.write_bytes(data)
        old.run(SimpleNamespace(manifest=path,source_manifest=a.source_manifest,manifest_sha256=hashlib.sha256(data).hexdigest(),out=a.out.with_name('parent-'+case+'-'+a.out.name)))
    # Enumerate every baseline failure for diagnosis, then fail closed before
    # any mutation count or qualification claim. Do not mask failures by cell order.
    diagnostics=[]
    for entry in m['cells']:
        path=Path(entry['file']);q.need(not path.is_absolute() and '..' not in path.parts,'CAPTURE_PATH')
        r=load(a.manifest.parent/path)
        q.need((r['profile'],r['cut'],r['optimized'],r['execution_case'])==(entry['profile'],entry['cut'],entry['optimized'],entry['execution_case']),'CELL_IDENTITY')
        try:
            one(r,sources);diagnostics.append(dict(file=entry['file'],baseline_checks='PASS'))
        except Exception as e:
            diagnostics.append(dict(file=entry['file'],baseline_checks='FAIL',error_type=type(e).__name__,error=str(e)))
    failures=[x for x in diagnostics if x['baseline_checks']=='FAIL']
    a.out.with_name(a.out.name.replace('execution-reader-','execution-diagnostic-')).write_bytes(q.canonical(
        dict(status='DIAGNOSTIC_ONLY',qualified=False,M1='HOLD',SR02='BLOCKED',cells=diagnostics)))
    q.need(not failures,'C_BASELINE_FAILURES_HOLD:'+json.dumps(failures,sort_keys=True))
    results=[];mutants=0
    for entry in m['cells']:
        path=Path(entry['file']);q.need(not path.is_absolute() and '..' not in path.parts,'CAPTURE_PATH')
        r=load(a.manifest.parent/path);q.need((r['profile'],r['cut'],r['optimized'],r['execution_case'])==(entry['profile'],entry['cut'],entry['optimized'],entry['execution_case']),'CELL_IDENTITY')
        results.append(one(r,sources))
        changes=[lambda z:z['execution']['before']['stores'].clear(),lambda z:z['execution']['activate']['response'].update(ok=not z['execution']['activate']['response']['ok'])]
        if r['cut']=='before_commit':
            changes += [lambda z:z['execution']['execute_grant']['grant']['body'].update(native_epoch=-1),lambda z:z['execution']['native_ready'].update(normal_native_constructor_called=False),
                lambda z:z['execution']['bad_signature']['response'].update(ok=True),lambda z:z['execution']['after_effect']['stores'][q.authority_names(z['profile'])[0]]['c_permit_consumptions']['rows'].append(['fake']),
                lambda z:z['execution']['history']['response']['result']['result'].update(status='FAKE')]
            changes += [lambda z:z['execution']['negative_probes']['bad_signature_bit']['request']['permit'].update(signature='00'*64)]
        for f in changes:
            bad=copy.deepcopy(r);f(bad);q.need(bad!=r,'MUTATION_ACTUALLY_CHANGES_EVIDENCE')
            try:one(bad,sources)
            except Exception:mutants+=1
            else:raise ValueError('EXECUTION_EVIDENCE_MUTATION_ACCEPTED')
    q.need(sum(x['C_effect'] for x in results)==12 and sum(x['historical'] for x in results)==28 and mutants==280,'EXACT_C_EXECUTION_COUNTS')
    q.need(not {'execution','activation','admission','retirement','native_bridge','sql_service','standard','recovery','participant'}&set(sys.modules),'OFFLINE_NO_IMPLEMENTATION_IMPORT')
    value=dict(status='C_NATIVE_EXECUTION_56_RECEIVED',parent_B_sigkills=56,C_commit_sigkills=12,normal_native_C_owners=40,supervised_fixture_rearms=28,C_effects=12,
        successful_no_cut_cells=4,post_commit_lost_reply_recoveries=4,pre_commit_rollback_holds=4,expired_after_precheck_refusals=4,revoked_after_precheck_refusals=4,
        historical_no_C_refusals=28,late_commit_limit_observations=4,late_precommit_rollback_holds=4,evidence_mutations_rejected_per_mode=mutants,results=results,M1='HOLD',SR02='BLOCKED',independent_audit=False,
        scope='Trusted root/OS/owner, retained stores, no clones; final clock sampled at staging, no bound through COMMIT; normal constructors with explicit C role adapter and fixture rearm')
    a.out.write_bytes(q.canonical(value));print(json.dumps({k:v for k,v in value.items() if k!='results'}))
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('manifest','source-manifest','out'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);run(p.parse_args())
