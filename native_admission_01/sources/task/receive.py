"""Saved evidence oracle for the new participant, no native engine imports."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from shared import CASES,get,need,commit_race
from original_verify import identity,peer

DOMAIN=b'FCI-TYPED-GUARD-ROLLBACK/1\0'
CERT=b'FCI-NATIVE-NONEXECUTION-CERTIFICATE/1\0'
PERMIT=b'SAME-K-NATIVE-BRIDGE-PERMIT/1\0'
RESULT=b'SAME-K-NATIVE-BRIDGE-RESULT/1\0'


def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def body_rows(s,store,table):return s['stores'][store][table]['rows']


def one(r,w,c,we,ce,verify,canonical,content_hash):
    profile,case=r['profile'],r['case'];context=w['context'];rid=context['allocation_B']['rid']
    need(profile in ('FCI','STANDARD') and case in CASES and r['status']=='CAPTURED_AWAITING_READER','CELL')
    need(w['request_B']==r['writer_ready']['request_B'] and context==r['writer_ready']['context'],'SIGNED_PREPARATION')
    ca=verify(context['certificate'],context['sink_public'],CERT)
    need(ca['key']==context['key'] and ca['content_hash']==context['h']==content_hash(context['content']) and
         ca['fenced_generation']==1,'A_CONTEXT')
    for req,uid,generation in ((context['request_A'],62023,1),(w['request_B'],62024,2)):
        p=verify(req['permit'],context['sink_public'],PERMIT)
        n=verify(req['native']['authorization'],context['issuer_public'],b'FCI-SQL-D2A-AUTHZ/1\0')
        need(p['key']==context['key'] and p['content_hash']==context['h'] and p['generation']==generation and
             p['subject_uid']==n['subject_uid']==uid and p['native_operation_id']==n['operation_id'] and
             p['native_digest']==digest(req['native']),'REQUEST_AUTHENTICATION')
        need(all(n[k]==context['content'][k] for k in ('target','action','expected_version','value')),'BUSINESS_BINDING')
    for name,x in (('writer',w),('certifier',c)):
        identity(x['identity']);identity(r[name+'_ready']['identity'])
        need(x['pid']==r[name+'_ready']['pid'] and x['ppid']==r['supervisor_pid']==r[name+'_ready']['ppid'],'SIBLING_IDENTITY')
    need(w['pid']!=c['pid'] and c['no_engine'] is True and w['actor']==62024 and c['actor']==62022,'SEPARATE_ACTORS')
    need(r['authority_inode_retained'] is r['private_pins_retained'] is True,'AUTHORITY_RETAINED')
    peer(r['writer_rpc'],62024);peer(r['control_rpc'],62022)
    need(r['writer_rpc']['response']['result']==w['response'] and r['control_rpc']['response']['result']==dict(response=c['response'],repeat=c['repeat']),'WIRE_BINDING')
    need([d['client_uid'] for d in r['writer_role_denials']]==[62023,62022,62025], 'WRITER_DENIAL_COVERAGE')
    for d,code in zip(r['writer_role_denials'],('WRITER_ROLE','WRITER_ROLE','UNKNOWN_UID')):
        peer(d,d['client_uid']);need(d['response']['ok'] is False and d['response']['error']==code,'WRITER_ROLE_DENIAL')
    need([d['client_uid'] for d in r['denials']]==[62023,62024,62025],'ROLE_PROBES')
    for d,code in zip(r['denials'],('CONTROL_ROLE','CONTROL_ROLE','UNKNOWN_UID')):
        peer(d,d['client_uid']);need(d['response']['ok'] is False and d['response']['error']==code,'ROLE_DENIAL')
    need([x['mode'] for x in r['waits']]==['writer','certifier'] and all(x['exit']==0 and x['waited'] is True for x in r['waits']),'CLEAN_WAITS')
    need(r['while_paused']['business']['native_effects']==r['while_paused']['business']['business_results']==[],'NO_EARLY_DURABLE_EFFECT')
    for snapshot in (r['while_paused'],r['after_guarded_writer'],r['final']):
        need(snapshot['reader_uid']==0 and snapshot['reader_pid']==r['supervisor_pid'],'ROOT_READBACK_IDENTITY')
    main='consumer.db' if profile=='FCI' else 'resource.db'
    raw=w['diagnostic_after']['sql'];root=r['after_guarded_writer']['diagnostic']
    need(raw['stores']==root['stores'] and raw['reader_pid']==w['pid'] and raw['reader_uid']==62021 and
         raw['read_only'] is root['read_only'] is True and raw['atomic_across_databases'] is False,'DURABLE_SNAPSHOT_BINDING')
    final=r['final']['business'];response=w['response'];native=w['after']['native_control']
    need(r['final']['business']==r['after_guarded_writer']['business'] and len(final['attempts'])==2 and final['business_rows']==1,'NO_POST_ACTION_OR_C')
    need(final['attempts'][0]==[1,62023,ca['fenced_native_operation_id'],'FENCED'],'A_RETAINED')
    attempt=next(e for e in ce if e['event']=='CERT_BEGIN_ATTEMPT' and e.get('call')=='primary')
    acquired=next(e for e in ce if e['event']=='CERT_BEGIN_ACQUIRED' and e.get('call')=='primary')
    returned=next(e for e in ce if e['event']=='PRIMARY_RETURNED')
    released=next(e for e in we if e['event']=='WRITER_RELEASED')
    need(r['pause']['ns']<attempt['ns']<=acquired['ns']<returned['ns'],'CERTIFICATE_ORDER')
    committed=case in ('COMMIT_FIRST','LOST_ACK_AFTER_COMMIT')
    if commit_race(case):
        need(r['pause']['point']=='before_commit' and r['pause']['in_transaction'] is True and len(r['pause']['staged_effects'])==1,'ACTUAL_NATIVE_STAGING')
        pending=r['pending_control_observation']
        need(pending['writer_alive'] is pending['certifier_alive'] is pending['control_pending'] is pending['no_acquired_event'] is True and
             attempt['ns']<pending['ns']<r['release_writer_ns']<=released['ns']<=acquired['ns'],'BLOCKED_REAL_CERTIFIER')
    else:
        need(r['pause']['point']=='after_precheck' and r['pause']['in_transaction'] is False and r['writer_live_at_certificate'] is True and
             returned['ns']<r['release_writer_ns']<=released['ns'],'FENCE_BEFORE_NATIVE_RESUME')
    if committed:
        need(len(final['native_effects'])==len(final['business_results'])==1 and final['native_effects'][0][0]==rid,'ONE_COMMITTED_EFFECT')
        env=final['business_results'][0];result=verify(env,context['sink_public'],RESULT)
        need(result['key']==context['key'] and result['content_hash']==context['h'] and result['native_operation_id']==rid and
             result['generation']==2 and result['subject_uid']==62024,'SIGNED_RESULT_BINDING')
        need(c['response']==c['repeat']==dict(disposition='RESULT_RETRIEVED',result=env) and len(r['final']['certificates'])==1,'R0_ONLY_NO_B_CERTIFICATE')
        need(final['attempts'][1]==[2,62024,rid,'APPLIED'],'APPLIED_RESULT')
        if case=='COMMIT_FIRST':need(response['status']=='NEW' and response['result']==env,'NORMAL_COMMIT_RETURN')
        else:
            need(response['status']=='HOLD_NATIVE' and any(e['event']=='WRITER_COMMIT_RETURNED' for e in we) and
                 any(e['event']=='REAL_COMMIT_ACK_LOST' for e in we),'REAL_COMMIT_ACK_LOST_NOT_REFUSED')
    else:
        need(final['native_effects']==final['business_results']==[] and final['attempts'][1]==[2,62024,rid,'FENCED'],'ZERO_EFFECT_CLOSED_B')
        cert=c['response']['certificate'];cb=verify(cert,context['sink_public'],CERT)
        need(cb['fenced_native_operation_id']==rid and cb['fenced_generation']==2 and cb['fenced_subject_uid']==62024 and
             cb['key']==context['key'] and cb['content_hash']==context['h'],'CERTIFICATE_B_BINDING')
        stored=r['final']['certificates'];need(len(stored)==2 and stored[1][2:]==[0,None],'CERTIFICATE_UNUSED_NO_C')
        actual=json.loads(stored[1][1])
        if case=='BAD_CERTIFICATE':
            need(r['certificate_fault']=='STORED_SIGNATURE_ONLY_AFTER_CERTIFICATE_BEFORE_RESUME' and r['certificate_before_tamper']==cert and
                 actual['body']==cert['body'] and actual['signature']=='0'*128,'DECLARED_BAD_CERTIFICATE')
        else:need(actual==cert,'EXACT_STORED_CERTIFICATE')
        need(not any(e['event']=='WRITER_COMMIT_RETURNED' for e in we),'NO_OLD_NATIVE_COMMIT')
        if case=='FENCE_FIRST':need(response['status']=='REFUSED' and response['code']=='STALE_ATTEMPT','NEW_EXPLICIT_REFUSAL')
        elif case=='FROZEN_CONTROL':
            need(response['status']==('HOLD_NATIVE' if profile=='FCI' else 'REFUSED'),'FROZEN_CONTROL_UNCHANGED')
        else:need(response['status']=='HOLD_NATIVE','AMBIGUOUS_OR_UNQUALIFIED_STAYS_HOLD')
    fact=w['participant'];qualified=case=='FENCE_FIRST'
    if case=='FROZEN_CONTROL':
        need(w['participant_disabled'] is True and fact is None,'TRUE_FROZEN_CONTROL')
    else:
        need(w['participant_disabled'] is False and fact['factory_is_new'] is True and fact['request_digest']==digest(w['request_B']),'PARTICIPANT_INVOCATION')
        ev=fact['events'];need(ev[0]['event']=='INVOCATION_ENTERED' and ev[-1]['event']=='PARTICIPANT_RESTORED','PARTICIPANT_COMPLETION')
        need(all(e['pid']==w['pid'] and e['uid']==62021 for e in ev),'PARTICIPANT_EVENT_IDENTITY')
        if qualified:
            env=response['refusal_witness'];proof=verify(env,context['sink_public'],DOMAIN)
            need(fact['receipt']==env and fact['rollback_returned'] is True and fact['commit_boundary'] is False and
                 fact['preimage']==fact['durable_postimage'],'REAL_ROLLBACK_PREIMAGE')
            need(proof['schema']=='NATIVE-TYPED-GUARD-ROLLBACK/1' and proof['profile']==profile and proof['key']==context['key'] and
                 proof['content_hash']==context['h'] and proof['rid']==rid and proof['generation']==2 and proof['uid']==62024 and
                 proof['request_digest']==digest(w['request_B']) and proof['invocation']==fact['invocation'] and proof['transaction']==fact['transaction'],
                 'SIGNED_WITNESS_BINDING')
            permit=w['request_B']['permit']['body'];cert=c['response']['certificate']
            need(proof['policy']==permit['policy'] and proof['epoch']==permit['epoch'] and proof['deployment']==context['key']['deployment'] and
                 proof['certificate_id']==cert['body']['certificate_id'] and proof['certificate_digest']==digest(cert),'CURRENT_WITNESS_AUTHORITY')
            need(proof['preimage_digest']==proof['durable_postimage_digest']==digest(fact['preimage']) and
                 proof['guard_type']=='authorization.AuthorizationRefused' and proof['guard_code']=='STALE_ATTEMPT' and
                 proof['rollback_returned'] is True and proof['commit_boundary'] is False and proof['execution_authorized'] is proof['recovery_authorized'] is False,
                 'ROLLBACK_WITNESS_NOT_A_PERMIT')
            need(proof['participant_source_sha256']==hashlib.sha256((HERE/'participant.py').read_bytes()).hexdigest(),'PARTICIPANT_SOURCE_BINDING')
            guards=[e for e in ev if e['event']=='PINNED_ADMIT_RAISED']
            need(len(guards)==1 and guards[0]['origin_received'] is True and guards[0]['code']=='STALE_ATTEMPT' and guards[0]['in_transaction'] is True,
                 'PINNED_NATIVE_GUARD_PROVENANCE')
            need(any(e['event']=='ROLLBACK_RETURNED' and e['in_transaction'] is False for e in ev) and
                 any(e['event']=='RECEIPT_QUALIFIED' for e in ev),'ACTUAL_ROLLBACK_RETURN_RECEIVED')
            need(response['availability']=='NOT_QUALIFIED' and response['execution_authorized'] is response['recovery_authorized'] is False,'NO_AVAILABILITY_OR_REARM_GRANT')
            expected_post=copy.deepcopy(fact['durable_postimage'])
            if profile=='FCI':
                cols=expected_post['d2_meta']['columns'];idx=cols.index('recovery')
                need(expected_post['d2_meta']['rows'][0][idx]==0,'PRE_HOLD_RECOVERY')
                expected_post['d2_meta']['rows'][0][idx]=1
            need(expected_post==root['stores'][main],'POST_ROLLBACK_ONLY_DECLARED_PROTECTIVE_HOLD')
        else:
            need(fact['receipt'] is None and 'refusal_witness' not in response,'UNQUALIFIED_HAS_NO_REFUSAL_WITNESS')
        if case=='ROLLBACK_DENIED':
            need(fact['rollback_returned'] is False and any(e['event']=='REAL_SQLITE_ROLLBACK_DENIED' for e in ev) and
                 any(e['event']=='ABORT_CLEANUP_RETURNED' for e in ev),'FAILED_FIRST_ROLLBACK_NOT_REPAIRED')
        if case=='INCOMPLETE_WITNESS':need(fact['preimage'] is None,'MISSING_PREIMAGE_NOT_INFERRED')
        if case=='COMMIT_DENIED':need(any(e['event']=='REAL_SQLITE_COMMIT_DENIED' for e in we),'REAL_SQLITE_COMMIT_ERROR')
    if profile=='FCI':
        auth=w['diagnostic_after']['authenticated_in_owner']
        spend=auth['spend'];ledger=body_rows(raw,'spend.db','ledger')
        need(json.loads(bytes.fromhex(ledger[0][1]['bytes_hex']))==spend,'SPEND_NATIVE_DECODER_TO_RAW_BINDING')
        histories={e['ticket']['token']['body']['request_id']:e for e in auth['history']}
        need({row[0]:json.loads(row[1]) for row in body_rows(raw,'consumer.db','inbox')}==histories,'INBOX_DECODER_TO_RAW_BINDING')
        need(histories[rid]['status']==('DONE' if committed else 'PENDING'),'FCI_NATIVE_INBOX_STATE')
        reserved=case in ('COMMIT_FIRST','LOST_ACK_AFTER_COMMIT','COMMIT_DENIED','POST_RESERVATION_ABORT')
        need((rid in spend['attempts']) is reserved,'REAL_FCI_SPEND_RESERVATION_BOUNDARY')
        if reserved:need(spend['attempts'][rid]['kind']=='EFFECT_ATTEMPT','SPEND_KIND')
        need((auth['fences'][rid] is not None) is committed,'NATIVE_COMMIT_FENCE_BOUNDARY')
        if case!='COMMIT_FIRST':need(native['poisoned'] is True and native['meta']['recovery']==1,'FCI_CONSERVATIVE_HOLD_RETAINED')
        if qualified:need(proof['spend_status']=='B_ABSENT','PROVEN_ABSENT_SPEND')
        if case=='POST_RESERVATION_ABORT':need(any(e['event']=='POST_RESERVATION_ABORT' and e['B_record_present'] is True for e in fact['events']),'ACTUAL_POST_RESERVATION_FAULT')
    else:
        need(w['diagnostic_after']['authenticated_in_owner'] is None and set(raw['stores'])=={'resource.db','reference.db'},'NO_ARTIFICIAL_STANDARD_LEDGER')
        phases={x[0]:x[1] for x in native['phases']}
        expected=('COMMITTED' if case=='COMMIT_FIRST' else 'RESERVED' if case in ('LOST_ACK_AFTER_COMMIT','COMMIT_DENIED','POST_RESERVATION_ABORT','OTHER_EXCEPTION') else 'QUARANTINED')
        need(phases[rid]==expected,'STANDARD_NATIVE_PHASE_RETAINED')
        if qualified:need(proof['spend_status']=='NOT_APPLICABLE','STANDARD_NO_FCI_SPEND_WITNESS')
    return dict(profile=profile,case=case,status=response['status'],qualified_refusal=qualified,
                official_effects=len(final['native_effects']),result_present=bool(final['business_results']),
                recovery_authorized=False,execution_authorized=False)


def receive(folder,support,mutations=False):
    folder=Path(folder);sys.path.insert(0,str(Path(support)/'fci-same-k-handoff-20261030'))
    from handoff import verify,canonical,content_hash
    rep=get(folder/'RESULTS.json');pins=get(HERE/'INPUTS.json')
    need(rep['campaign']=='TYPED-REFUSAL-NATIVE/1' and rep['status']=='CAPTURED_AWAITING_READER' and
         rep['cases']==rep['expected_cases']==20 and rep['failures']==0 and get(folder/'FAILURES.json')==[],'COMPLETE_NEW_NATIVE_SUITE')
    for name,h in rep['own_sources'].items():need(hashlib.sha256((HERE/name).read_bytes()).hexdigest()==h,'OWN_SOURCE_PIN')
    for x in pins['files']:
        prefix=x['argument'].removesuffix('_root');need(rep['copied_sources'][prefix+'/'+x['path']]==x['sha256'],'FROZEN_SUPPORT_PIN')
    manifest=get(Path(support)/'fci-same-k-handoff-20261030/NATIVE_SOURCES.json')
    need(all(rep['copied_sources']['native/'+p]==h for p,h in manifest['files'].items()),'FROZEN_37_ENGINES')
    need(rep['copied_sources']['task/wire.py']==pins['wire']['sha256'],'FROZEN_WIRE')
    need(all(rep['copied_sources']['task/'+p]==h for p,h in rep['own_sources'].items() if p.endswith('.py')),'RUNTIME_NEW_SOURCE_PIN')
    originals=[];results=[]
    for profile in ('FCI','STANDARD'):
        for case in CASES:
            p=folder/(profile+'__'+case)
            args=[get(p/'report.json'),get(p/'writer.json'),get(p/'certifier.json'),
                  [json.loads(x) for x in (p/'writer.jsonl').read_text().splitlines()],
                  [json.loads(x) for x in (p/'certifier.jsonl').read_text().splitlines()]]
            need(args[0]['profile']==profile and args[0]['case']==case,'FOLDER_BINDING')
            results.append(one(*args,verify,canonical,content_hash));originals.append(args)
    rejected=[]
    if mutations:
        def bad_witness_signature(a):
            for envelope in (a[1]['response']['refusal_witness'],a[1]['participant']['receipt'],a[0]['writer_rpc']['response']['result']['refusal_witness']):
                envelope['signature']='0'*128
        choices=[
            (0,'wrong_kernel_uid',lambda a:a[0]['writer_rpc']['response']['peer'].update(uid=62023)),
            (0,'no_rollback',lambda a:a[1]['participant'].update(rollback_returned=False)),
            (0,'preimage_substitution',lambda a:a[1]['participant'].update(preimage={})),
            (0,'fake_witness_signature',bad_witness_signature),
            (0,'spent_certificate',lambda a:a[0]['final']['certificates'][1].__setitem__(2,1)),
            (0,'missing_guard_origin',lambda a:next(e for e in a[1]['participant']['events'] if e['event']=='PINNED_ADMIT_RAISED').update(origin_received=False)),
            (3,'lost_ack_called_refusal',lambda a:a[1]['response'].update(status='REFUSED',code='STALE_ATTEMPT')),
            (4,'hidden_commit_error',lambda a:a.__setitem__(3,[e for e in a[3] if e['event']!='REAL_SQLITE_COMMIT_DENIED'])),
            (5,'failed_rollback_promoted',lambda a:a[1]['participant'].update(rollback_returned=True)),
            (7,'false_bad_certificate',lambda a:a[0].update(certificate_fault='NOT_INJECTED')),
            (8,'fabricated_preimage',lambda a:a[1]['participant'].update(preimage={})),
            (9,'lost_surviving_spend',lambda a:a[1]['diagnostic_after']['authenticated_in_owner']['spend'].update(attempts={})),
        ]
        for idx,name,mutate in choices:
            args=copy.deepcopy(originals[idx]);before=copy.deepcopy(args);mutate(args);need(args!=before,'NOOP_MUTANT')
            try:one(*args,verify,canonical,content_hash)
            except (ValueError,KeyError,TypeError,StopIteration):rejected.append(name)
            else:raise ValueError('MUTANT_ACCEPTED:'+name)
    need(sum(x['qualified_refusal'] for x in results)==2 and sum(x['official_effects'] for x in results)==4,'COUNTS')
    return dict(status='RECEIVED_SCOPED_TYPED_REFUSAL_NATIVE_PARTICIPANT',native_cells=20,optimized=rep['optimized'],
        qualified_refusals=2,official_effects=4,role_denials=120,saved_mutations_rejected=len(rejected),mutants=rejected,results=results,
        new_composition=True,core_engine_files_modified=False,hot_recovery_qualified=False,original_PR430_reclassified=False,
        independent_audit=False,full_authority_restore=False,universal_no_bypass=False,comparative_advantage=False,M1='HOLD')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('folder',type=Path);p.add_argument('--support-root',type=Path,required=True)
    p.add_argument('--mutations',action='store_true');a=p.parse_args()
    print(json.dumps(receive(a.folder,a.support_root,a.mutations),sort_keys=True))
