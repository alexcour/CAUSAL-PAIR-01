"""Saved live attestations, frozen crash oracle, and v2 decision-sidecar checks."""
import argparse,hashlib,json,sys,importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import quiescence as q
def run(a):
    spec=importlib.util.spec_from_file_location('frozen_crash_reader',HERE/'receive.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    original=old.run(a)
    manifest=json.loads(a.manifest.read_text());sources=json.loads(a.source_manifest.read_text())
    q.need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==sources['files']['crash/v2_receive.py']
        and q.policy_hash()==sources['files']['crash/quiescence.py'],'V2_GATE_AND_RECEIVER_SOURCES')
    results=[];sidecars=0;root_public=None
    for entry in manifest['cells']:
        row=json.loads((a.manifest.parent/entry['file']).read_text());ctx=row['v2_context'];proof=row['v2_attestation'];w=row['writer_ready'];positive=row['cut']=='after_commit'
        q.need(ctx['birth']==row['pidfd_birth'] and ctx['birth']['pid']==w['pid'] and ctx['birth']['uid']==62021
            and proof['body']['wait']==row['pidfd_wait'] and ctx['supervisor_public']==row['supervisor_public'],'LIVE_KERNEL_BINDING')
        q.need(row['pidfd_kernel_uids']==[62021]*4,'KERNEL_PROCESS_UIDS')
        q.need(ctx['supervisor_pid']==row['root_before']['reader_pid'] and ctx['supervisor_uid']==0,'ROOT_COLLECTOR_IDENTITY')
        root_public=root_public or row['supervisor_public'];q.need(root_public==row['supervisor_public'],'ONE_EPHEMERAL_ROOT_KEY')
        boundary=row['root_context_boundary'];q.need(boundary==dict(directory_uid=0,directory_mode=0o755,context_uid=0,context_mode=0o444,proof_uid=0,proof_mode=0o444),'ROOT_OWNED_CONTEXT_FILES')
        omitted=row['v2_proof_unavailability'];q.need(omitted['absent_during_probe'] is omitted['no_autocreate'] is omitted['restored_unchanged'] is True,'REAL_V2_PROOF_UNAVAILABILITY')
        files=row['authority_inventory'];q.need(set(files)==set(q.authority_names(row['profile']))
            and {n:x['sha256'] for n,x in files.items()}==row['db_hashes_before'],'AUTHORITY_INVENTORY_SQL_BYTES')
        calls=row['retained_reads']+[row['missing_authority_read'],row['missing_supervisor_read'],row['restored_read']]
        for index,call in enumerate(calls):
            v=call['response']['result'];body=q.verify(v['gate_v2'],row['trust_anchors']['sink'],q.DECISION)
            current=dict(files)
            if index==2:current.pop('spend.db' if row['profile']=='FCI' else 'reference.db')
            pf=None if index==3 else proof;decision=q.decide(ctx,pf,w,v['state'],current)
            q.need(body==dict(schema='FCI-QUIESCENCE-DECISION/2',query_id='abcde'[index]*32,uid=62023,context_digest=q.digest(ctx),proof_digest=q.digest(pf),state_digest=q.digest(v['state']),decision=decision),'SIGNED_DECISION_AND_PROOF_BINDING')
            q.need(decision['execution_authorized'] is decision['recovery_authorized'] is decision['new_execution'] is False,'NO_RETRY_OR_REARM_GRANT')
            if index==2:q.need(decision['code']=='AUTHORITY_FILE_UNAVAILABLE' and decision['quiescence']=='ATTESTED_TERMINATED_OWNER','AUTHORITY_HOLD_INDEPENDENT_OF_DEATH')
            elif index==3:q.need(decision['code']=='SUPERVISOR_PROOF_UNAVAILABLE' and decision['quiescence']=='UNATTESTED','PROOF_MISSING_HOLD')
            else:
                q.need(decision['quiescence']=='ATTESTED_TERMINATED_OWNER' and decision['authority']=='RETAINED_VIEW_VERIFIED'
                    and decision['outcome']==('RESULT_VERIFIED' if positive else 'NATIVE_B_UNRESOLVED')
                    and decision['decision']==('HISTORICAL_RESULT_ONLY' if positive else 'HOLD'),'THREE_DISTINCT_DECISIONS')
                q.need(decision['code']==('RESULT_RETRIEVED_NO_REEXECUTION' if positive else 'NATIVE_B_UNRESOLVED'),'EXACT_RESULT_OR_UNRESOLVED_HOLD')
            sidecars+=1
        final=q.decide(ctx,proof,w,row['root_after']['stores'],files)
        results.append(dict(profile=row['profile'],cut=row['cut'],optimized=row['optimized'],quiescence=final['quiescence'],outcome=final['outcome'],decision=final['decision'],native_phase=final['native_phase']))
    q.need(len(results)==8 and sidecars==40 and sum(x['decision']=='HISTORICAL_RESULT_ONLY' for x in results)==4,'LIVE_COUNTS')
    q.need(not {'sql_service','standard','native_bridge','participant','attribution','recovery'}&set(sys.modules),'OFFLINE_NO_ENGINE_IMPORTS')
    result=dict(status='QUIESCENCE_V2_EIGHT_LIVE_RECEIVED',native_sigkills=8,kernel_bound_termination_attestations=8,
        historical_results_only=4,unresolved_native_B_holds=4,signed_query_decisions=40,missing_authority_holds=8,missing_proof_holds=8,
        frozen_crash_reader_still_received=True,results=results,recovery_authorized=False,authority_restored=False,independent_audit=False,M1='HOLD',SR02='BLOCKED')
    a.out.write_bytes(q.canonical(result));print(json.dumps({k:v for k,v in result.items() if k!='results'}))
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('manifest','source-manifest','out'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);run(p.parse_args())
