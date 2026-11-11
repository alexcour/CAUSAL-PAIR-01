"""Independent activation/permit receipt oracle; imports no activation/native code."""
import argparse,copy,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE.parent/'crash'))
import quiescence as q
GRANT=b'FCI-C-ACTIVATION-GRANT/1\0';CERT=b'FCI-C-ACTIVATION/1\0';PERMIT=b'FCI-C-EXECUTION-PERMIT/1\0';RPC=b'FCI-C-ACTIVATION-RPC/1\0'
def load(p):return json.loads(p.read_text())
def peer(c,uid):
    q.need(c['client_uid']==uid and c['response']['peer']==dict(pid=c['client_pid'],uid=uid,gid=uid),'ACTIVATION_KERNEL_IDENTITY');return c['response']
def result(c,uid,op,pin,policy):
    w=peer(c,uid);q.need(w['ok'] is True,'ACTIVATION_RPC_OK');v=w['result'];b=q.verify(v['receipt'],pin,RPC)
    q.need(b==dict(schema='FCI-C-ACTIVATION-RPC/1',op=op,uid=uid,result_digest=q.digest(v['result']),activation_policy=policy,
        native_execution_called=False,rearm_called=False),'SIGNED_ACTIVATION_RPC');return v['result']
def denied(c,uid,code):
    w=peer(c,uid);q.need(w['ok'] is False and w['error']==code,'EXACT_ACTIVATION_REFUSAL:'+code)
def one(r,policy):
    profile=r['profile'];pending=r['cut']=='before_commit';main=q.authority_names(profile)[0];pin=r['trust_anchors']['sink'];before=r['activation_before']['stores'];after=r['activation_after']['stores']
    q.need(before==r['admission_final']['stores'],'SEPARATE_ACTIVATION_PHASE')
    g=q.verify(r['activation_grant'],r['supervisor_public'],GRANT)
    q.need(g['schema']=='FCI-C-ACTIVATION-GRANT/1' and g['scope']==r['v2_context']['scope'] and g['state_digest']==q.digest(before)
        and g['activation_policy']==policy and type(g['not_before']) is type(g['not_after']) is int and g['not_after']==g['not_before']+120,'ROOT_FRESH_ACTIVATION_GRANT')
    q.need(g['owner_wait']==r['admission_restart_wait' if pending else 'admission_wait'] and g['owner_wait']['waited'] is True and g['owner_wait']['exit']==-15,'ADMISSION_OWNER_WAIT_BEFORE_ACTIVATION')
    q.need(r['activation_grant_boundary']==dict(uid=0,mode=0o444,parent_uid=0,parent_mode=0o755),'ROOT_ACTIVATION_BOUNDARY')
    for name in ('activation_owner_ready',)+(('activation_restart_ready',) if pending else ()):
        ready=r[name];i=ready['identity'];q.need(i['uid']==i['euid']==62021 and i['dumpable']==0 and i['no_new_privs']=='1' and int(i['cap_eff'],16)==0
            and ready['sink_public']==pin and ready['native_execution_called'] is ready['normal_native_constructor_called'] is ready['rearm_called'] is False,'HARDENED_ACTIVATION_OWNER')
        wait=r['activation_restart_wait' if name=='activation_restart_ready' else 'activation_wait'];q.need(wait==dict(pid=ready['pid'],exit=-15,waited=True),'ACTIVATION_OWNER_WAITED')
    for call,uid,code in zip(r['activation_role_denials'],(62023,62024,62026,62025),('CONTROL_ROLE','CONTROL_ROLE','CONTROL_ROLE','UNKNOWN_UID')):denied(call,uid,code)
    orig=g['inventory'];final=r['activation_final_inventory'];q.need(set(orig)==set(final)==set(q.authority_names(profile)),'COMPLETE_ACTIVATION_AUTHORITY')
    for n,x in final.items():
        q.need({k:v for k,v in x.items() if k!='sha256'}=={k:v for k,v in orig[n].items() if k!='sha256'} and (pending and n==main or x['sha256']==orig[n]['sha256']),'ACTIVATION_AUTHORITY_RETAINED')
    if not pending:
        denied(r['activation_historical_refusal'],62022,'ADMITTED_C_REQUIRED');q.need(before==after and all(not before[main][n]['rows'] for n in ('c_activations','c_permits','c_activation_events')),'HISTORICAL_RESULT_NEVER_ACTIVATES_C')
        return dict(profile=profile,cut=r['cut'],activated=False,native_permits=0)
    codes={'missing_grant':'AUTHORITY_UNAVAILABLE','missing_authority':'ACTIVATION_AUTHORITY_MISSING','bad_scope':'ACTIVATION_GRANT_BINDING',
        'bad_stale_view':'ACTIVATION_BASELINE_CHANGED','bad_expired_grant':'ACTIVATION_GRANT_EXPIRED','bad_policy':'ACTIVATION_GRANT_BINDING'}
    for name,code in codes.items():denied(r['activation_'+name],62022,code)
    q.need(r['activation_after_refusals']['stores']==before,'ACTIVATION_REFUSALS_WRITE_NOTHING')
    get=lambda name,uid,op:result(r['activation_'+name],uid,op,pin,policy)
    q.need(get('abort',62022,'abort_activation')==dict(status='ABORT_ROLLED_BACK',stores_unchanged=True),'ACTIVATION_REAL_ROLLBACK')
    active=get('close',62022,'activate_C');repeat=get('repeat',62022,'activate_C');restarted=get('restart_cert',62022,'activate_C')
    cert=active['certificate'];cb=q.verify(cert,pin,CERT);ads=q.rows(before,main,'native_admissions');q.need(len(ads)==1,'ONE_ADMISSION_BEFORE_ACTIVATION');admission=json.loads(ads[0]['envelope']);allocation=admission['body']['allocation']
    q.need(g['admission_digest']==q.digest(admission) and cb==dict(schema='FCI-C-ACTIVATION/1',grant_digest=q.digest(r['activation_grant']),admission_digest=q.digest(admission),allocation=allocation,
        activation_policy=policy,execution_route='VERSIONED_PERMIT_GATE',native_execution_qualified=False),'EXACT_ACTIVATION_CERTIFICATE')
    q.need(active==dict(status='C_ACTIVATED',certificate=cert,new_activation=True) and repeat==restarted==dict(status='ACTIVATION_RETRIEVED',certificate=cert,new_activation=False),'IDEMPOTENT_ACTIVATION_AND_RESTART')
    long=get('issue',62022,'issue_C');again=get('issue_repeat',62022,'issue_C');restart_issue=get('restart_issue',62022,'issue_C');short=get('short_issue',62022,'issue_C')
    q.need(long['status']==short['status']=='PERMIT_ISSUED' and long['new_permit'] is short['new_permit'] is True
        and again==restart_issue==dict(status='PERMIT_RETRIEVED',permit=long['permit'],request=long['request'],new_permit=False),'IDEMPOTENT_DURABLE_PERMIT')
    business=q.rows(before,main,'sk_business')[0];content=json.loads(business['content']);requests=[]
    for item,challenge,ttl in ((long,'a'*32,25),(short,'b'*32,2)):
        p=q.verify(item['permit'],pin,PERMIT);req=item['request'];legacy=q.verify(req['permit'],pin,b'SAME-K-NATIVE-BRIDGE-PERMIT/1\0')
        native=q.verify(req['native']['authorization'],r['trust_anchors']['issuer'],b'FCI-SQL-D2A-AUTHZ/1\0')
        q.need(p==dict(schema='FCI-C-EXECUTION-PERMIT/1',challenge=challenge,ttl=ttl,grant_digest=q.digest(r['activation_grant']),activation_digest=q.digest(cert),
            allocation=allocation,request_digest=q.digest(req),epoch=g['control'][1],policy=g['control'][0],boot_id=g['boot_id'],not_before=legacy['not_before'],not_after=legacy['not_after'],
            activation_policy=policy,route='VERSIONED_PERMIT_GATE'),'EXACT_VERSIONED_PERMIT')
        q.need(legacy['schema']=='BRIDGE-PERMIT/1' and legacy['key']==allocation['key'] and legacy['content_hash']==allocation['h'] and legacy['generation']==3
            and legacy['attempt_id']==allocation['attempt_id'] and legacy['subject_uid']==62026 and legacy['native_operation_id']==allocation['rid']
            and legacy['native_digest']==q.digest(req['native']) and legacy['policy']==g['control'][0] and legacy['epoch']==g['control'][1]
            and type(legacy['not_before']) is type(legacy['not_after']) is int and legacy['not_after']==legacy['not_before']+ttl
            and g['not_before']<=legacy['not_before']<legacy['not_after']<=g['not_after'],'FROZEN_BRIDGE_SIGNED_PERMIT')
        q.need(native['subject_uid']==62026 and native['subject_role']=='requester' and native['operation_id']==allocation['rid'] and native['policy_digest']==g['control'][0]
            and native['boot_id']==g['boot_id'] and native['deployment_id']==allocation['key']['deployment']
            and req['native']['op']=='execute' and all(native[k]==v for k,v in req['native']['operation'].items())
            and all(native[k]==content[k] for k in ('target','action','expected_version','value')),'ISSUER_SIGNED_NATIVE_C_AUTHORIZATION')
        requests.append((challenge,q.canonical(item['permit']).decode(),q.canonical(req).decode()))
    valid=dict(status='C_PERMIT_VALID_AT_GATE',native_execution_called=False,rearm_called=False,new_effect=False)
    for name in ('valid_check','short_valid','restart_valid'):q.need(get(name,62026,'authorize_C')==valid,'DRY_GATE_ONLY_NO_EXECUTION')
    for call,uid in zip(r['activation_early_issue_roles'],(62024,62026)):denied(call,uid,'CONTROL_ROLE')
    for call,uid in zip(r['activation_check_role_denials'],(62022,62024)):denied(call,uid,'C_ROLE')
    for name,uid,code in [('wrong_ttl',62022,'CHALLENGE_PARAMETERS_CHANGED'),('tampered_permit',62026,'SIGNATURE_INVALID'),('tampered_request',62026,'PERMIT_BINDING'),
        ('bare_permit',62026,'SIGNATURE_INVALID'),('short_expired',62026,'PERMIT_EXPIRED'),('short_reissue',62022,'PERMIT_EXPIRED'),
        ('revoked_check',62026,'C_REVOKED'),('revoked_issue',62022,'C_NOT_ACTIVE'),('revoked_reactivate',62022,'C_REVOKED')]:denied(r['activation_'+name],uid,code)
    clock=r['activation_expiry_clock'];q.need(clock['boot_id']==g['boot_id'] and clock['deadline']==short['permit']['body']['not_after'] and clock['observed']>=clock['deadline'],'REAL_MONOTONIC_EXPIRY')
    q.need(get('revoke',62022,'revoke_C')==dict(status='C_REVOKED',new_revocation=True) and get('revoke_repeat',62022,'revoke_C')==dict(status='C_REVOKED',new_revocation=False),'IDEMPOTENT_REVOCATION')
    projected=copy.deepcopy(after);m=projected[main]
    q.need(q.rows(after,main,'c_activations')==[dict(rid=allocation['rid'],envelope=q.canonical(cert).decode(),status='REVOKED')],'DURABLE_REVOKED_ACTIVATION')
    q.need(q.rows(after,main,'c_permits')==[dict(challenge=c,envelope=e,request=req) for c,e,req in requests],'TWO_DURABLE_PERMITS_ONLY')
    events=q.rows(after,main,'c_activation_events');wanted=[('C_ACTIVATED',q.digest(cert)),('C_PERMIT_ISSUED',q.digest(long['permit'])),('C_PERMIT_ISSUED',q.digest(short['permit'])),('C_REVOKED',q.digest(cert))]
    q.need(events==[dict(seq=i+1,event=e,digest=d) for i,(e,d) in enumerate(wanted)],'EXACT_ACTIVATION_EVENT_SEQUENCE')
    for n in ('c_activations','c_permits','c_activation_events'):m[n]['rows']=[]
    t=m['sk_attempts'];matches=[x for x in t['rows'] if x[t['columns'].index('rid')]==allocation['rid']];q.need(len(matches)==1 and matches[0][t['columns'].index('state')]=='FENCED','REVOKED_C_FENCED');matches[0][t['columns'].index('state')]='ADMISSION_ONLY'
    t=m['sk_control'];idx=t['columns'].index('epoch');q.need(t['rows'][0][idx]==g['control'][1]+1,'REVOCATION_ADVANCES_EPOCH');t['rows'][0][idx]-=1
    q.need(projected==before,'ONLY_DECLARED_ACTIVATION_PERMIT_REVOCATION_DELTA')
    q.need(r['activation_pre_restart']['stores']==r['activation_before_revoke']['stores'],'RESTART_AND_CHECKS_WRITE_NOTHING')
    opened=r['activation_after_open']['stores'];checks=r['activation_after_checks']['stores'];expected=copy.deepcopy(opened);expected[main]['c_permits']['rows']=[[v for v in requests[0]]]
    expected[main]['c_activation_events']['rows']=[[1,'C_ACTIVATED',q.digest(cert)],[2,'C_PERMIT_ISSUED',q.digest(long['permit'])]]
    q.need(expected==checks,'REPEAT_AND_REFUSAL_PROBES_ADD_NO_PERMITS')
    return dict(profile=profile,cut=r['cut'],activated=True,native_permits=2)
def run(a):
    spec=importlib.util.spec_from_file_location('prior_admission_reader',HERE.parent/'admission/receive.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old);old.run(a)
    sources=load(a.source_manifest);q.need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==sources['files']['activation/receive.py'],'ACTIVATION_RECEIVER_SOURCE');policy=sources['files']['activation/activation.py']
    results=[];mutants=0
    for entry in load(a.manifest)['cells']:
        r=load(a.manifest.parent/entry['file']);results.append(one(r,policy))
        changes=[lambda x:x['activation_grant_boundary'].update(uid=62021),lambda x:x['activation_owner_ready'].update(rearm_called=True),
            lambda x:x['activation_role_denials'][0]['response'].update(ok=True),lambda x:x['activation_after']['stores'].clear()]
        if r['cut']=='before_commit':changes += [lambda x:x['activation_valid_check']['response']['result']['result'].update(native_execution_called=True),
            lambda x:x['activation_issue_repeat']['response']['result']['result'].update(new_permit=True),
            lambda x:x['activation_expiry_clock'].update(observed=x['activation_expiry_clock']['deadline']-1),
            lambda x:x['activation_revoke_repeat']['response']['result']['result'].update(new_revocation=True),
            lambda x:x['activation_grant']['body'].update(state_digest='0'*64),lambda x:x['activation_short_reissue']['response'].update(ok=True),
            lambda x:x['activation_restart_ready'].update(normal_native_constructor_called=True),lambda x:x['activation_revoked_check']['response'].update(ok=True)]
        for change in changes:
            bad=copy.deepcopy(r);change(bad);q.need(bad!=r,'MUTATION_MUST_CHANGE_EVIDENCE')
            try:one(bad,policy)
            except Exception:mutants+=1
            else:raise ValueError('ACTIVATION_EVIDENCE_MUTATION_ACCEPTED')
    q.need(len(results)==8 and sum(x['activated'] for x in results)==4 and sum(x['native_permits'] for x in results)==8 and mutants==64,'EXACT_ACTIVATION_COUNTS')
    q.need(not {'activation','admission','retirement','native_bridge','sql_service','standard','participant'}&set(sys.modules),'OFFLINE_NO_IMPLEMENTATION_IMPORT')
    out=dict(status='C_ACTIVATION_AND_PERMIT_EIGHT_RECEIVED',native_sigkills=8,activated_C=4,historical_activation_refusals=4,activation_rollbacks=4,
        native_permits_issued=8,kernel_role_denials=48,activation_grant_authority_holds=24,real_expiry_cases=4,revocation_cases=4,restart_retrievals=4,
        dry_gate_authorizations=12,activation_evidence_mutations=mutants,C_executed=False,normal_native_service_restart_qualified=False,
        independent_audit=False,legacy_reservations_preserved=True,M1='HOLD',SR02='BLOCKED',results=results)
    a.out.write_bytes(q.canonical(out));print(json.dumps({k:v for k,v in out.items() if k!='results'}))
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('manifest','source-manifest','out'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);run(p.parse_args())
