"""Frozen crash/quiescence readers plus bounded terminal-retirement receipt checks."""
import argparse,copy,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path[:0]=[str(HERE),str(HERE.parent/'crash')]
import quiescence as q
DOMAIN=b'FCI-NATIVE-RETIREMENT/1\0';RPC=b'FCI-NATIVE-RETIREMENT-RPC/1\0'
def load(p):return json.loads(p.read_text())
def projected(stores,profile,rid):
    s=copy.deepcopy(stores);main=s[q.authority_names(profile)[0]]
    q.need(len(main['native_retirements']['rows'])==len(main['native_retirement_events']['rows'])==1,'ONE_TERMINAL_RECORD')
    main['native_retirements']['rows']=[];main['native_retirement_events']['rows']=[]
    t=main['sk_attempts'];rr=t['columns'].index('rid');ss=t['columns'].index('state')
    found=[x for x in t['rows'] if x[rr]==rid];q.need(len(found)==1 and found[0][ss]=='FENCED','FENCED_B');found[0][ss]='OPEN';return s
def peer(call,uid):
    q.need(call['client_uid']==uid and call['response']['peer']==dict(pid=call['client_pid'],uid=uid,gid=uid),'KERNEL_RPC_IDENTITY');return call['response']
def result(call,uid,op,pin):
    wire=peer(call,uid);q.need(wire['ok'] is True,'RETIREMENT_RPC_OK');r=wire['result'];b=q.verify(r['receipt'],pin,RPC)
    q.need(b==dict(schema='FCI-NATIVE-RETIREMENT-RPC/1',op=op,uid=uid,result_digest=q.digest(r['result']),execution_authorized=False,recovery_authorized=False,handoff_authorized=False),'SIGNED_RETIREMENT_RPC');return r['result']
def one(r,policy):
    profile=r['profile'];pending=r['cut']=='before_commit';main=q.authority_names(profile)[0];pin=r['trust_anchors']['sink'];ctx=r['v2_context'];proof=r['v2_attestation']
    ready=r['retirement_owner_ready'];i=ready['identity'];q.need(i['uid']==i['euid']==62021 and i['dumpable']==0 and i['no_new_privs']=='1' and int(i['cap_eff'],16)==0,'HARDENED_CLOSURE_OWNER')
    q.need(ready['normal_service_constructor_called'] is ready['rearm_called'] is False and ready['sink_public']==pin
        and r['reader_stopped_before_retirement'] is True,'NO_NATIVE_STARTUP_REARM')
    wait=r['retirement_wait'];q.need(wait['pid']==ready['pid'] and wait['waited'] is True and type(wait['exit']) is int,'CLOSURE_OWNER_WAITED')
    before=r['retirement_before']['stores'];after=r['retirement_after']['stores'];end=r['retirement_after_probes']['stores']
    q.need(before==r['root_after']['stores'] and after==end,'SEPARATE_STABLE_RETIREMENT_PHASE')
    for call,uid,code in zip(r['retirement_denials'],(62023,62024,62025),('CONTROL_ROLE','CONTROL_ROLE','UNKNOWN_UID')):
        w=peer(call,uid);q.need(w['ok'] is False and w['error']==code,'CLOSURE_CONTROL_DENIAL')
    close=result(r['retirement_close'],62022,'close_B',pin);repeat=result(r['retirement_repeat'],62022,'close_B',pin)
    probes=result(r['retirement_probes'],62024,'probe_B',pin)
    q.need(probes['normal_service_constructor_called'] is probes['rearm_called'] is probes['allocation_C_created'] is False,'NO_STARTUP_OR_C')
    expected_tables=copy.deepcopy(before)
    if not pending:
        q.need(close['status']==repeat['status']=='HISTORICAL_RESULT_ONLY' and close['new_retirement'] is repeat['new_retirement'] is False
            and before==after and after[main]['native_retirements']['rows']==[] and probes['retired'] is False
            and probes['historical_result_verified'] is True,'COMMITTED_RESULT_NEVER_NONEXECUTION_RETIREMENT')
        return dict(profile=profile,cut=r['cut'],status='HISTORICAL_RESULT_ONLY',new_retirement=False,guarded_routes=0)
    abort=result(r['retirement_abort'],62022,'abort_retirement_trial',pin)
    q.need(abort==dict(status='ABORT_ROLLED_BACK',injected_fault=True,stores_unchanged=True),'REAL_SQL_ABORT_NO_TERMINAL_DELTA')
    q.need(close['status']=='CAPABILITY_RETIRED' and close['new_retirement'] is True and repeat['status']=='RETIREMENT_RETRIEVED'
        and repeat['new_retirement'] is False and close['certificate']==repeat['certificate'],'IDEMPOTENT_TERMINAL_RETIREMENT')
    cert=close['certificate'];body=q.verify(cert,pin,DOMAIN);rid=ctx['scope']['native_operation_id']
    q.need(body['schema']=='FCI-NATIVE-RETIREMENT/1' and body['scope']==ctx['scope'] and body['termination_proof_digest']==q.digest(proof)
        and body['preimage_digest']==q.digest(before)==proof['body']['state_digest'] and body['retirement_policy_sha256']==policy
        and body['disposition']=='CAPABILITY_RETIRED_NO_EFFECT' and body['legacy_native_state_preserved'] is True
        and body['handoff_authorized'] is body['execution_authorized'] is body['recovery_authorized'] is body['independent_attestation'] is False,'TYPED_TERMINAL_CERTIFICATE')
    q.need(projected(after,profile,rid)==before,'ONLY_APPEND_RETIREMENT_AND_FENCE')
    stored=q.rows(after,main,'native_retirements');events=q.rows(after,main,'native_retirement_events')
    q.need(stored[0]['rid']==events[0]['rid']==rid and json.loads(stored[0]['envelope'])==cert and events[0]['event']=='CAPABILITY_RETIRED'
        and events[0]['certificate_digest']==q.digest(cert),'DURABLE_CERTIFICATE_AND_EVENT')
    detail=body['native_evidence'];q.need(probes['retired'] is True and probes['native_decoder']==detail,'PROBE_REUSES_AUTHENTICATED_NATIVE_VIEW')
    if profile=='FCI':
        q.need(r['marker']['retirement_reservation_cut'] is True,'ACTUAL_POST_RESERVATION_CUT')
        q.need(detail['consumer_status']=='PENDING' and detail['native_phase']=='PREPARED' and detail['fence'] is None
            and detail['reservation']['kind']=='EFFECT_ATTEMPT','FCI_HISTORY_NOT_RELABELLED_CANCELLED')
        raw=q.rows(before,'spend.db','ledger')[0];payload=json.loads(bytes.fromhex(raw['payload']['bytes_hex']))
        q.need(q.digest(payload)==detail['spend_digest'] and payload['attempts'][rid]==detail['reservation'],'FROZEN_MAC_DECODER_TO_RAW_SPEND_BINDING')
        expected={'bridge_execute','native_execute','native_handle_finish','consumer_finish','consumer_receive','consumer_cancel'}
        consumer=next(x for x in probes['frozen_routes'] if x['route']=='frozen_consumer_finish');q.need(consumer['code']=='BLOCK_EFFECT_UNCERTAIN','PRESERVED_SPEND_GUARD_STILL_BLOCKS')
    else:
        q.need(detail['native_phase']=='RESERVED' and detail['inspection']['effect_status']=='UNKNOWN' and detail['reservation_retained'] is True,'STANDARD_RESERVATION_PRESERVED')
        expected={'bridge_execute','native_execute'}
    routes=probes['guarded_routes'];q.need(len(routes)==len(expected) and {x['route'] for x in routes}==expected
        and all(x['result']==dict(code='BLOCK_NATIVE_RETIRED',new_effect=False) for x in routes),'VERSIONED_NATIVE_ENTRIES_CLOSED')
    raw=next(x for x in probes['frozen_routes'] if x['route']=='frozen_bridge_execute');q.need(raw['code']=='STALE_ATTEMPT','FROZEN_BUSINESS_FENCE')
    raw=next(x for x in probes['frozen_routes'] if x['route']=='frozen_native_execute');q.need(raw['result']['effect_status']=='UNKNOWN'
        and raw['result']['new_effect'] is not True,'FROZEN_NATIVE_NEVER_REEXECUTES_RESERVED_B')
    q.need(probes['legacy_redeem_probe']['accepted'] is False and len(q.rows(after,main,'sk_attempts'))==2
        and len(q.rows(after,main,'sk_certificates'))==1,'RETIREMENT_NOT_HANDOFF_NO_C')
    return dict(profile=profile,cut=r['cut'],status='CAPABILITY_RETIRED',new_retirement=True,guarded_routes=len(routes))
def run(a):
    spec=importlib.util.spec_from_file_location('frozen_quiescence_reader',HERE.parent/'crash/v2_receive.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old);old.run(a)
    manifest=load(a.manifest);sources=load(a.source_manifest);policy=sources['files']['retirement/retirement.py']
    q.need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==sources['files']['retirement/receive.py'],'RETIREMENT_RECEIVER_SOURCE')
    results=[];mutants=0
    for entry in manifest['cells']:
        r=load(a.manifest.parent/entry['file']);results.append(one(r,policy))
        mutations=[lambda x:x['retirement_owner_ready'].update(rearm_called=True),lambda x:x['retirement_after_probes']['stores'].clear(),
            lambda x:x['retirement_denials'][0]['response'].update(ok=True),lambda x:x['retirement_wait'].update(waited=False)]
        for mutate in mutations:
            bad=copy.deepcopy(r);mutate(bad)
            try:one(bad,policy)
            except Exception:mutants+=1
            else:raise ValueError('RETIREMENT_EVIDENCE_MUTANT_ACCEPTED')
    q.need(len(results)==8 and sum(x['new_retirement'] for x in results)==4 and sum(x['guarded_routes'] for x in results)==16,'EXACT_RETIREMENT_COUNTS')
    q.need(not {'native_bridge','participant','attribution','recovery','sql_service','standard','retirement'}&set(sys.modules),'OFFLINE_NO_NATIVE_CONSTRUCTION_OR_IMPORT')
    output=dict(status='NATIVE_RETIREMENT_OVERLAY_EIGHT_RECEIVED',native_sigkills=8,retired_B_capabilities=4,historical_results_only=4,
        rollback_trials=4,control_denials=24,guarded_native_route_denials=16,legacy_handoff_rejections=4,retirement_evidence_mutants=mutants,
        legacy_reservations_preserved=True,native_legacy_cancelled=False,normal_service_restart_qualified=False,allocation_C_created=False,
        execution_authorized=False,recovery_authorized=False,independent_audit=False,M1='HOLD',SR02='BLOCKED',results=results)
    a.out.write_bytes(q.canonical(output));print(json.dumps({k:v for k,v in output.items() if k!='results'}))
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('manifest','source-manifest','out'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);run(p.parse_args())
