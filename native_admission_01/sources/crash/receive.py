"""Independent saved-capture reader. Never imports engines or producer modules."""
import argparse,copy,hashlib,json,sys
from pathlib import Path
PARTICIPANT='c86e4d661fbf87984d61e851cdd40710a8c9bbbb2032f815a2f579530094a6ba'
AUTH=b'GUARDED-PRODUCER-AUTH/1\0';EFFECT=b'GUARDED-PRODUCER-EFFECT/1\0';QUERY=b'GUARDED-CRASH-READ/1\0'
def need(ok,why):
    if not ok:raise ValueError(why)
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def digest(x):return hashlib.sha256(canon(x)).hexdigest()
def verify(e,pin,domain):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    need(set(e)=={'body','signature'},'SIGNED_SHAPE');Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin)).verify(bytes.fromhex(e['signature']),domain+canon(e['body']));return e['body']
def identity(i):
    need(i['uid']==i['euid']==62021 and i['dumpable']==0 and i['no_new_privs']=='1' and int(i['cap_eff'],16)==0,'HARDENED_OWNER')
def peer(call,uid):
    need(call['client_uid']==uid and call['response']['peer']==dict(pid=call['client_pid'],uid=uid,gid=uid),'KERNEL_PEER');return call['response']
def one(r):
    need(r['status']=='CAPTURED','CAPTURED');profile=r['profile'];cut=r['cut'];committed=cut=='after_commit'
    need(profile in ('FCI','STANDARD') and cut in ('before_commit','after_commit'),'CELL_IDENTITY')
    w=r['writer_ready'];rr=r['reader_ready'];identity(w['identity']);identity(rr['identity']);anchors=r['trust_anchors'];c=w['context'];base=w['request_B'];p=base['permit']['body']
    need(anchors==dict(issuer=c['issuer_public'],sink=c['sink_public']) and rr['sink_public']==anchors['sink'],'ROOT_KEYS')
    need(w['gate']['status']=='CONSISTENT_FOR_SUPERVISED_REARM' and w['helper']['status']=='READY','PREPARATORY_RETAINED_AUTHORITY_GATE')
    need(r['preparation_wait']['exit']==0 and r['preparation_wait']['waited'] is True
        and r['preparation_wait']['pid']==r['preparation']['pid'] and r['preparation']['final_state']['native_effects']==[],'PREPARATION_WAITED_NO_EFFECT')
    cert=verify(c['certificate'],anchors['sink'],b'FCI-NATIVE-NONEXECUTION-CERTIFICATE/1\0')
    permit=verify(base['permit'],anchors['sink'],b'SAME-K-NATIVE-BRIDGE-PERMIT/1\0')
    native=verify(base['native']['authorization'],anchors['issuer'],b'FCI-SQL-D2A-AUTHZ/1\0')
    need(cert['fenced_generation']==1 and permit['generation']==2 and permit['subject_uid']==native['subject_uid']==62024
        and permit['key']==cert['key']==c['key'] and permit['native_operation_id']==native['operation_id']==c['allocation_B']['rid']
        and permit['native_digest']==digest(base['native']),'SIGNED_A_B_CONTEXT')
    auth=w['producer_authorization'];a=verify(auth,anchors['issuer'],AUTH)
    need(a==dict(schema='GUARDED-PRODUCER-AUTH/1',profile=profile,invocation_id=a['invocation_id'],uid=62024,generation=2,
        request_digest=digest(base),key=c['key']) and len(a['invocation_id'])==32,'PRODUCER_AUTH')
    marker=r['marker'];part=marker['participant']
    need(marker['pid']==w['pid'] and marker['uid']==62021 and marker['point']==cut
        and marker['in_transaction'] is (not committed) and marker['request']==base and marker['producer_authorization']==auth,'ACTUAL_CUT_MARKER')
    need(part['request_digest']==digest(base) and part['scope_restored'] is False and part['receipt'] is None
        and type(part['transaction']) is str and len(part['transaction'])==32
        and not any(e['event']=='PARTICIPANT_RESTORED' for e in part['events']),'PARTICIPANT_KILLED_BEFORE_RETURN')
    need(r['writer_rpc']==dict(client_pid=r['writer_rpc']['client_pid'],client_uid=62024,exit=r['writer_rpc']['exit'],error='NATIVE_EOF_NO_ACK')
        and r['writer_rpc']['exit']!=0,'NO_SUCCESS_ACK')
    waits={x['mode']:x for x in r['waits']}
    need(set(waits)=={'writer','reader'} and all(x['waited'] is True for x in waits.values())
        and waits['writer']['pid']==w['pid'] and waits['writer']['exit']==-9
        and waits['reader']['pid']==rr['pid'] and type(waits['reader']['exit']) is int and rr['pid']!=w['pid'],'ACTUAL_SIGKILL_AND_READER_WAIT')
    need(r['supervisor_B']==dict(old_process_waited=True,old_exit=-9,old_pid=w['pid'],single_owner_no_clones=True,
        authority_inode=r['supervisor_B']['authority_inode']),'SIGKILL_NOT_RELABELED_CLEAN_EXIT')
    need(rr['native_engine_constructed'] is rr['rearm_called'] is False and r['private_pins_retained'] is True,'NO_RESTART_REARM')
    recovery=r['storage_recovery'];need(recovery['kind']=='SQLITE_OPEN_RW_SELECT_FOR_HOT_JOURNAL_RECOVERY'
        and recovery['native_engine_constructed'] is recovery['new_business_execute'] is False,'STORAGE_RECOVERY_ONLY')
    before=r['root_before'];after=r['root_after'];stores=before['stores'];main_name='consumer.db' if profile=='FCI' else 'resource.db';main=stores[main_name]
    need(before['reader_uid']==after['reader_uid']==0 and before['read_only'] is after['read_only'] is True
        and stores==after['stores'] and r['db_hashes_before']==r['db_hashes_after'],'READ_ONLY_STATES_AND_DATABASE_BYTES')
    def product(m):
        side=m['producer_results']['rows'];business=m['sk_business']['rows'];need(len(side)==len(business)==1,'ONE_PRODUCER_AND_RESULT')
        env=json.loads(side[0][2]);legacy=json.loads(business[0][3]);body=verify(env,anchors['sink'],EFFECT);old=verify(legacy,anchors['sink'],b'SAME-K-NATIVE-BRIDGE-RESULT/1\0')
        need(old['key']==p['key'] and old['content_hash']==p['content_hash'] and old['native_operation_id']==p['native_operation_id']
            and old['generation']==2 and old['subject_uid']==62024,'LEGACY_RESULT')
        need(body==dict(schema='GUARDED-PRODUCER-EFFECT/1',profile=profile,producer_invocation=a['invocation_id'],
            participant_invocation=part['invocation'],participant_sha256=PARTICIPANT,uid=62024,generation=2,auth_digest=digest(auth),
            request_digest=digest(base),legacy_digest=digest(legacy),native_operation_id=p['native_operation_id'],effect_id=old['effect_id'],
            key=p['key'],content_hash=p['content_hash'],target=old['target'],old_version=old['old_version'],new_version=old['new_version'],value=old['value']),'PRODUCER_PARTICIPANT_EFFECT')
        need(side[0][:2]==[canon(p['key']).decode(),a['invocation_id']],'SQL_PRODUCER_INDEX');return env,legacy
    staged_product,staged_legacy=product(marker['main'])
    effects=main['demo_effects' if profile=='FCI' else 'effects']['rows']
    # Native schema column ordering is received explicitly, not guessed.
    table=main['demo_effects' if profile=='FCI' else 'effects'];mapped=[dict(zip(table['columns'],x)) for x in effects]
    conf=main['demo_configuration' if profile=='FCI' else 'configuration'];configs={x[conf['columns'].index('target')]:dict(zip(conf['columns'],x)) for x in conf['rows']}
    need(configs['synthetic-config']['value']==configs['synthetic-config']['version']==int(committed)
        and configs['synthetic-config-decoy']['value']==configs['synthetic-config-decoy']['version']==0,'EXACT_CONFIGURATION')
    if committed:
        need(len(mapped)==1 and mapped[0]['operation_id']==p['native_operation_id'] and mapped[0]['old_version']==0
            and mapped[0]['new_version']==mapped[0]['value']==1,'ONE_COMMITTED_NATIVE_EFFECT')
        need(product(main)==(staged_product,staged_legacy),'COMMITTED_PRODUCT_EXACTLY_RETRIEVED')
    else:
        need(mapped==[] and main['producer_results']['rows']==[] and main['sk_business']['rows'][0][3] is None,'STAGED_SIGNATURE_NOT_DURABILITY')
    f=r['authority_unavailability'];need(f['absent_during_probe'] is f['no_autocreate'] is f['restored'] is True and f['hash_before']==f['hash_after'],'AUTHORITY_UNAVAILABLE_NO_REPAIR')
    f=r['supervisor_unavailability'];need(f['absent_during_probe'] is f['no_autocreate'] is f['restored'] is f['unchanged'] is True,'SUPERVISOR_UNAVAILABLE_NO_REPAIR')
    calls=r['retained_reads']+[r['missing_authority_read'],r['missing_supervisor_read'],r['restored_read']]
    need(len(calls)==5 and len({x['client_pid'] for x in calls})==5,'FIVE_REAL_QUERY_PROCESSES')
    for index,call in enumerate(calls):
        wire=peer(call,62023);need(wire['ok'] is True,'QUERY_OK');v=wire['result'];q=verify(v['query'],anchors['sink'],QUERY)
        missing=index==2;super_missing=index==3
        gate=dict(status='HOLD',code='AUTHORITY_FILE_UNAVAILABLE',missing=['spend.db' if profile=='FCI' else 'reference.db']) if missing else dict(status='HOLD',code='SUPERVISOR_PROOF_UNAVAILABLE' if super_missing else 'QUIESCENCE_NOT_ESTABLISHED')
        expected_state=None if missing else stores;expected_producer=staged_product if committed and not missing else None;expected_legacy=staged_legacy if committed and not missing else None
        outcome='HISTORICAL_PRODUCER_RESULT' if committed and not missing else 'HOLD_OUTCOME_UNAVAILABLE'
        need(v['state']==expected_state and v['producer']==expected_producer and v['legacy']==expected_legacy
            and v['gate']==gate and v['outcome']==outcome and v['gate_called'] is (not missing and not super_missing)
            and v['new_execution'] is v['execution_authorized'] is v['recovery_authorized'] is False,'READ_OUTCOME_DISTINCT_FROM_RETRY_PERMISSION')
        need(q==dict(schema='GUARDED-CRASH-READ/1',profile=profile,query_id='abcde'[index]*32,uid=62023,outcome=outcome,
            state_digest=digest(expected_state),legacy_digest=digest(expected_legacy),producer_digest=digest(expected_producer),gate=gate,
            gate_called=not missing and not super_missing,new_execution=False,execution_authorized=False,recovery_authorized=False),'SIGNED_QUERY_NONCE_AND_VIEW')
    wrong=peer(r['wrong_role'],62024);need(wrong['ok'] is False and wrong['error']=='READ_ROLE','WRONG_READER_REFUSED')
    return dict(profile=profile,cut=cut,effect_count=int(committed),staged_receipt_not_durability=not committed,read_only_queries=5,recovery_gate='HOLD_QUIESCENCE_NOT_ESTABLISHED')
def run(a):
    raw=a.manifest.read_bytes();need(hashlib.sha256(raw).hexdigest()==a.manifest_sha256,'EXTERNAL_CAPTURE_MANIFEST')
    m=json.loads(raw);source=json.loads(a.source_manifest.read_text());need(m['sources']==source and hashlib.sha256(a.source_manifest.read_bytes()).hexdigest()==m['source_manifest_sha256'],'SOURCE_MANIFEST_BINDING')
    need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==source['files']['crash/receive.py'],'RECEIVER_SOURCE')
    need(source['files']['task/participant.py']==PARTICIPANT,'PINNED_PARTICIPANT_SOURCE')
    need(len(m['cells'])==8 and {(x['profile'],x['cut'],x['optimized']) for x in m['cells']}=={(p,c,o) for p in ('FCI','STANDARD') for c in ('before_commit','after_commit') for o in (False,True)},'EXACT_EIGHT')
    results=[];rejected=0
    for entry in m['cells']:
        path=Path(entry['file']);need(not path.is_absolute() and '..' not in path.parts,'CONFINED_REPORT')
        r=json.loads((a.manifest.parent/path).read_text());need((r['profile'],r['cut'],r['optimized'])==(entry['profile'],entry['cut'],entry['optimized']),'FOLDER_BINDING');results.append(one(r))
        mutations=[lambda x:x['supervisor_B'].update(old_exit=86),lambda x:x['marker'].update(pid=0),
            lambda x:x['db_hashes_after'].update(fake='0'*64),lambda x:x['reader_ready'].update(rearm_called=True),
            lambda x:x['retained_reads'][0]['response']['result'].update(recovery_authorized=True),
            lambda x:x['retained_reads'][1].update(response=copy.deepcopy(x['retained_reads'][0]['response'])),
            lambda x:x['authority_unavailability'].update(no_autocreate=False),lambda x:x['trust_anchors'].update(sink='00'*32)]
        for mutate in mutations:
            bad=copy.deepcopy(r);mutate(bad)
            try:one(bad)
            except Exception:rejected+=1
            else:raise ValueError('SAVED_EVIDENCE_MUTANT_ACCEPTED')
    need(not {'native_bridge','participant','attribution','sql_service','standard','recovery'}&set(sys.modules),'INDEPENDENT_READER_IMPORTS')
    out=dict(status='GUARDED_CRASH_EIGHT_RECEIVED',native_sigkills=8,committed_effects=4,precommit_cells=4,read_only_queries=40,
        missing_authority_probes=8,missing_supervisor_probes=8,wrong_role_denials=8,rejected_evidence_mutants=rejected,results=results,
        sqlite_storage_recovery_explicit=True,recovery_authorized=False,authority_restored=False,independent_audit=False,M1='HOLD',SR02='BLOCKED')
    a.out.write_bytes(canon(out));print(json.dumps({k:v for k,v in out.items() if k!='results'}))
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('manifest','source-manifest','out'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);run(p.parse_args())
