"""Offline C admission oracle. Does not import admission/native implementations."""
import argparse,copy,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE.parent/'crash'))
import quiescence as q
GRANT=b'FCI-NATIVE-C-ADMISSION-GRANT/1\0';RECEIPT=b'FCI-NATIVE-C-ADMISSION/1\0';RPC=b'FCI-NATIVE-C-ADMISSION-RPC/1\0'
def load(p):return json.loads(p.read_text())
def peer(call,uid):
    q.need(call['client_uid']==uid and call['response']['peer']==dict(pid=call['client_pid'],uid=uid,gid=uid),'ADMISSION_KERNEL_PEER');return call['response']
def result(call,op,pin):
    w=peer(call,62022);q.need(w['ok'] is True,'ADMISSION_RPC_OK');r=w['result'];b=q.verify(r['receipt'],pin,RPC)
    q.need(b==dict(schema='FCI-NATIVE-C-ADMISSION-RPC/1',op=op,uid=62022,result_digest=q.digest(r['result']),execution_authorized=False,recovery_authorized=False),'ADMISSION_RPC_SIGNATURE');return r['result']
def one(r,policy):
    profile=r['profile'];main=q.authority_names(profile)[0];pending=r['cut']=='before_commit';pin=r['trust_anchors']['sink']
    before=r['admission_before']['stores'];after=r['admission_after']['stores'];end=r['admission_final']['stores']
    q.need(before==r['retirement_after_probes']['stores'] and after==end,'DISTINCT_ADMISSION_PHASE')
    g=q.verify(r['admission_grant'],r['supervisor_public'],GRANT)
    q.need(g==dict(schema='FCI-NATIVE-C-ADMISSION-GRANT/1',grant_id=g['grant_id'],scope=r['v2_context']['scope'],
        retirement_digest=q.digest(r['retirement_close']['response']['result']['result'].get('certificate')) if pending else None,
        state_digest=q.digest(before),authority_inventory=g['authority_inventory'],successor_uid=62026,generation=3,
        admission_policy_sha256=policy,retirement_owner_wait=r['retirement_wait'],no_live_clones_assumed=True,
        execution_authorized=False,recovery_authorized=False),'FRESH_SIGNED_GRANT')
    q.need(type(g['grant_id']) is str and len(g['grant_id'])==32 and r['retirement_wait']['exit']==-15
        and r['retirement_wait']['waited'] is True,'GRANT_AFTER_WAIT')
    q.need(r['admission_grant_boundary']==dict(uid=0,mode=0o444,parent_uid=0,parent_mode=0o755),'ROOT_GRANT_BOUNDARY')
    for call,uid,code in zip(r['admission_denials'],(62023,62024,62026,62025),('CONTROL_ROLE','CONTROL_ROLE','CONTROL_ROLE','UNKNOWN_UID')):
        w=peer(call,uid);q.need(w['ok'] is False and w['error']==code,'ADMISSION_ROLE_REFUSED')
    for name in ('admission_owner_ready',)+(('admission_restart_ready',) if pending else ()):
        ready=r[name];i=ready['identity'];q.need(i['uid']==i['euid']==62021 and i['dumpable']==0 and i['no_new_privs']=='1'
            and int(i['cap_eff'],16)==0 and ready['sink_public']==pin and ready['normal_service_constructor_called'] is ready['rearm_called'] is False,'ADMISSION_HARDENED_OWNER')
        wait=r['admission_restart_wait' if name=='admission_restart_ready' else 'admission_wait']
        q.need(wait==dict(pid=ready['pid'],exit=-15,waited=True),'ADMISSION_OWNER_WAITED')
    inventory=r['admission_final_inventory'];q.need(set(inventory)==set(g['authority_inventory'])==set(q.authority_names(profile)),'COMPLETE_ADMISSION_AUTHORITY')
    for n,entry in inventory.items():
        orig=g['authority_inventory'][n]
        q.need({k:v for k,v in entry.items() if k!='sha256'}=={k:v for k,v in orig.items() if k!='sha256'}
            and (n==main and pending or entry['sha256']==orig['sha256']),'PRESERVED_AUTHORITY_IDENTITIES')
    if not pending:
        w=peer(r['admission_historical_refusal'],62022);q.need(w['ok'] is False and w['error']=='INTERNAL_HOLD'
            and before==after and q.rows(after,main,'native_admissions')==[] and len(q.rows(after,main,'sk_attempts'))==2,'COMMITTED_B_NEVER_ADMITS_C')
        return dict(profile=profile,cut=r['cut'],C_admitted=False,status='HISTORICAL_ONLY_ADMISSION_REFUSED')
    q.need(r['admission_after_refusals']['stores']==before,'REFUSALS_DO_NOT_WRITE')
    for name in ('admission_missing_grant','admission_missing_authority','admission_cross_scope','admission_stale_view'):
        w=peer(r[name],62022);q.need(w['ok'] is False and w['error']=='INTERNAL_HOLD','ADMISSION_FAULT_HOLD')
    abort=result(r['admission_abort'],'abort_admission_trial',pin);q.need(abort==dict(status='ABORT_ROLLED_BACK',stores_unchanged=True),'ADMISSION_ROLLBACK')
    pair=[result(c,'admit_C',pin) for c in r['admission_pair']]
    q.need(sorted(x['new_allocation'] for x in pair)==[False,True] and {x['status'] for x in pair}=={'C_ADMITTED_ONLY','ADMISSION_RETRIEVED'}
        and pair[0]['receipt']==pair[1]['receipt'],'ONE_ALLOCATION_TWO_OVERLAPPING_REQUESTS')
    receipt=pair[0]['receipt'];b=q.verify(receipt,pin,RECEIPT);a=b['allocation'];p=r['writer_ready']['request_B']['permit']['body']
    q.need(set(a)=={'key','h','generation','attempt_id','uid','rid'} and a['key']==p['key'] and a['h']==p['content_hash']
        and type(a['generation']) is int and a['generation']==3 and type(a['uid']) is int and a['uid']==62026
        and type(a['attempt_id']) is str and len(a['attempt_id'])==32,'EXACT_SUCCESSOR_C')
    q.need(a['rid']==hashlib.sha256(b'SAME-K-NATIVE-ATTEMPT/1\0'+q.canonical([a['key'],a['h'],3,a['attempt_id'],62026])).hexdigest(),'C_NATIVE_RID')
    ret=r['retirement_close']['response']['result']['result']['certificate']
    q.need(b==dict(schema='FCI-NATIVE-C-ADMISSION/1',grant_digest=q.digest(r['admission_grant']),retirement_digest=q.digest(ret),
        retirement_id=ret['body']['retirement_id'],allocation=a,admission_policy_sha256=policy,state='ADMISSION_ONLY',
        execution_authorized=False,recovery_authorized=False,native_permit_issued=False),'EXACT_ADMISSION_RECEIPT')
    for name in ('admission_repeat','admission_restart_read'):
        v=result(r[name],'admit_C',pin);q.need(v==dict(status='ADMISSION_RETRIEVED',new_allocation=False,receipt=receipt),'SAME_DURABLE_C_AFTER_RESTART')
    for name in ('admission_issue_probe','admission_restart_issue_probe'):
        v=result(r[name],'probe_issue_C',pin);q.need(v==dict(code='STALE_ALLOCATION',native_permit_issued=False,normal_service_constructor_called=False,rearm_called=False),'FROZEN_ISSUE_REFUSES_ADMISSION_ONLY')
    # Independently remove only the permitted delta and compare every other table/store.
    projected=copy.deepcopy(after);m=projected[main]
    ads=q.rows(after,main,'native_admissions');events=q.rows(after,main,'native_admission_events')
    q.need(len(ads)==len(events)==1 and ads[0]==dict(retirement_id=b['retirement_id'],grant_id=g['grant_id'],envelope=q.canonical(receipt).decode())
        and events[0]==dict(seq=1,event='C_ADMITTED_ONLY',grant_id=g['grant_id'],receipt_digest=q.digest(receipt)),'ATOMIC_ADMISSION_RECORD_AND_EVENT')
    m['native_admissions']['rows']=[];m['native_admission_events']['rows']=[]
    t=m['sk_attempts'];idx=t['columns'].index('rid');rr=[x for x in t['rows'] if x[idx]==a['rid']]
    q.need(len(t['rows'])==3 and len(rr)==1 and dict(zip(t['columns'],rr[0]))==dict(k=q.canonical(a['key']).decode(),g=3,attempt_id=a['attempt_id'],uid=62026,rid=a['rid'],state='ADMISSION_ONLY'),'ADMISSION_ONLY_NOT_OPEN')
    t['rows'].remove(rr[0]);q.need(projected==before,'ONLY_DECLARED_C_ALLOCATION_DELTA')
    return dict(profile=profile,cut=r['cut'],C_admitted=True,status='C_ADMITTED_ONLY_NO_EXECUTION')
def run(a):
    spec=importlib.util.spec_from_file_location('frozen_retirement_reader',HERE.parent/'retirement/receive.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old);old.run(a)
    sources=load(a.source_manifest);manifest=load(a.manifest);policy=sources['files']['admission/admission.py']
    q.need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==sources['files']['admission/receive.py'],'ADMISSION_RECEIVER_SOURCE')
    results=[];mutants=0
    for entry in manifest['cells']:
        r=load(a.manifest.parent/entry['file']);results.append(one(r,policy))
        mutations=[lambda x:x['admission_grant_boundary'].update(uid=62021),lambda x:x['admission_owner_ready'].update(rearm_called=True),
            lambda x:x['admission_final']['stores'].clear(),lambda x:x['admission_denials'][0]['response'].update(ok=True),
            lambda x:x['admission_grant']['body'].update(successor_uid=62024),lambda x:x['admission_wait'].update(waited=False)]
        if r['cut']=='before_commit':mutations += [lambda x:x['admission_pair'][1]['response']['result']['result'].update(new_allocation=not x['admission_pair'][1]['response']['result']['result']['new_allocation']),
            lambda x:x['admission_restart_read']['response']['result']['result'].update(new_allocation=True),
            lambda x:x['admission_after']['stores'][q.authority_names(x['profile'])[0]]['sk_attempts']['rows'][-1].__setitem__(-1,'OPEN')]
        for mutation in mutations:
            bad=copy.deepcopy(r);mutation(bad)
            try:one(bad,policy)
            except Exception:mutants+=1
            else:raise ValueError('ADMISSION_EVIDENCE_MUTANT_ACCEPTED')
    q.need(len(results)==8 and sum(x['C_admitted'] for x in results)==4 and mutants==60,'EXACT_ADMISSION_COUNTS')
    q.need(not {'admission','retirement','native_bridge','sql_service','standard','attribution','participant'}&set(sys.modules),'OFFLINE_NO_NATIVE_OR_ADMISSION_IMPORT')
    output=dict(status='C_ADMISSION_ONLY_EIGHT_RECEIVED',native_sigkills=8,admitted_C=4,historical_admission_refusals=4,
        role_denials=32,authority_grant_fault_holds=16,real_admission_rollbacks=4,overlapping_client_pairs=4,
        durable_restart_retrievals=4,frozen_issue_refusals=8,evidence_mutants=mutants,results=results,
        native_permit_issued=False,C_executed=False,normal_native_service_restart_qualified=False,legacy_reservations_preserved=True,
        independent_audit=False,M1='HOLD',SR02='BLOCKED')
    a.out.write_bytes(q.canonical(output));print(json.dumps({k:v for k,v in output.items() if k!='results'}))
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('manifest','source-manifest','out'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);run(p.parse_args())
