"""Read-only C004 extraction from pinned received native artifact13979046352.

No engine/repair/execution imports. ZIP identity is verified locally; extracted
CI input is bound by a content inventory computed from that verified ZIP.
"""
import argparse,copy,hashlib,importlib.util,json,zipfile
from pathlib import Path
PARENT_SHA='3ffa2f423c5a929ff5daa4b8a2f42dae5d54444e86ad8d2e74e233a1a18862de'
TREE_SHA='756bb95ccdd6f82cac254527f2ea928e809df3b592b7acba8b3c2ad1f4d08205'
SOURCE_SHA='3b7e067deb2849af9c2fc73cacd91b60166ea84153b006f892f371680501d1d4'
COMMIT='ca05c516877379d588e6af6bcc271d28ec68195e'
def need(x,why):
    if not x:raise ValueError(why)
def digest(b):return hashlib.sha256(b).hexdigest()
def inputs(a):
    if a.parent_zip:
        raw=a.parent_zip.read_bytes();need(len(raw)==3743671 and digest(raw)==PARENT_SHA,'EXACT_PARENT_ZIP')
        with zipfile.ZipFile(a.parent_zip) as z:
            need(z.testzip() is None,'PARENT_CRC');files={x.filename:z.read(x) for x in z.infolist() if not x.is_dir()}
        identity='EXACT_ZIP_HASH_SIZE_AND_CRC'
    else:
        files={p.relative_to(a.parent_dir).as_posix():p.read_bytes() for p in a.parent_dir.rglob('*') if p.is_file()};identity='EXTRACTED_CONTENT_INVENTORY'
    for name in files:
        p=Path(name);need(not p.is_absolute() and '..' not in p.parts and '\\' not in name,'CONFINED_PARENT_FILE')
    inv={n:dict(bytes=len(b),sha256=digest(b)) for n,b in files.items()}
    need(len(files)==433 and digest(json.dumps(inv,sort_keys=True,separators=(',',':')).encode())==TREE_SHA,'PINNED_PARENT_CONTENT_INVENTORY')
    need(files['EXECUTED_COMMIT.txt'].decode().strip()==COMMIT and digest(files['source-manifest.json'])==SOURCE_SHA,'PARENT_SOURCE_IDENTITY')
    return files,identity
def one(r,sources,q):
    x=r['execution'];case=r['execution_case'];main='consumer.db' if r['profile']=='FCI' else 'resource.db';sink=r['trust_anchors']['sink'];controller=x['issue']
    need(r['cut']=='before_commit' and case in ('expired_before_commit','expired_before_commit_kill'),'NATIVE_TEMPORAL_CASE')
    need(controller['client_uid']==62022 and controller['response']['peer']==dict(pid=controller['client_pid'],uid=62022,gid=62022) and controller['response']['ok'] is True,'NATIVE_KERNEL_ISSUER_PEER')
    issued=controller['response']['result'];rpc=q.verify(issued['receipt'],sink,b'FCI-C-NATIVE-EXECUTION-RPC/1\0');item=issued['result']
    policy=q.digest(dict(schema='FCI-C-EXECUTION-POLICY/2',files={n:sources['files']['execution/'+n] for n in ('execution.py','native_finalization.py')}))
    need(rpc==dict(schema='FCI-C-NATIVE-EXECUTION-RPC/1',op='issue_C',uid=62022,result_digest=q.digest(item),execution_policy=policy),'NATIVE_ISSUE_RPC_BINDING')
    p=q.verify(item['permit'],sink,b'FCI-C-NATIVE-CONSUMABLE-PERMIT/1\0');rid=p['allocation']['rid'];request=item['request']
    need(p['execution_policy']==policy and p['request_digest']==q.digest(request) and p['allocation']['uid']==62026 and p['allocation']['generation']==3,'NATIVE_PERMIT_SCOPE')
    grant=q.verify(x['execute_grant']['grant'],r['supervisor_public'],b'FCI-C-NATIVE-TRANSITION-GRANT/1\0')
    need(grant['purpose']=='EXECUTE' and grant['execution_policy']==policy and p['grant_digest']==q.digest(x['execute_grant']['grant']) and grant['boot_id']==p['boot_id'],'NATIVE_ROOT_GRANT')
    bp=q.verify(request['permit'],sink,b'SAME-K-NATIVE-BRIDGE-PERMIT/1\0');auth=q.verify(request['native']['authorization'],r['trust_anchors']['issuer'],b'FCI-SQL-D2A-AUTHZ/1\0')
    need(bp['native_operation_id']==auth['operation_id']==rid and bp['native_digest']==q.digest(request['native']) and bp['not_after']==p['not_after'],'NATIVE_SIGNED_REQUEST')
    marker=x['temporal_marker'];d=p['not_after'];release=x['temporal_release_tick']
    need(marker['pid']==p['owner_pid']==x['native_ready']['pid'] and marker['uid']==62021 and marker['point']=='before_commit' and marker['deadline']==d,'NATIVE_PAUSE_PROGRAM_POINT')
    need(p['not_before']<=marker['tick']<d<=release and x['after_effect']['ns']>=release*1_000_000_000,'NATIVE_CAUSAL_DEADLINE_BOUND')
    sql=x['after_effect']['stores'];effects=q.rows(sql,main,'demo_effects' if r['profile']=='FCI' else 'effects');cons=q.rows(sql,main,'c_permit_consumptions');business=q.rows(sql,main,'sk_business')[0]
    late=case=='expired_before_commit'
    need(len(effects)==len(cons)==int(late),'NATIVE_EFFECT_CONSUMPTION_ATOMICITY')
    if late:
        result=json.loads(business['result']);body=q.verify(result,sink,b'SAME-K-NATIVE-BRIDGE-RESULT/1\0');c=cons[0]
        need(body['native_operation_id']==effects[0]['operation_id']==c['rid']==rid and body['generation']==3 and body['subject_uid']==62026,'NATIVE_EFFECT_RESULT_SCOPE')
        need(c['permit_digest']==q.digest(item['permit']) and c['result_digest']==q.digest(result) and p['not_before']<=c['checked_tick']<d,'NATIVE_VALID_LAST_SAMPLE_WITH_LATE_EFFECT')
        history=x['history'];need(history['client_uid']==62026 and history['response']['ok'] is True and history['response']['peer']==dict(pid=history['client_pid'],uid=62026,gid=62026),'NATIVE_HISTORY_PEER')
        v=history['response']['result'];h=q.verify(v['receipt'],sink,b'FCI-C-NATIVE-EXECUTION-RPC/1\0')
        need(h['op']=='history_C' and h['uid']==62026 and h['execution_policy']==policy and h['result_digest']==q.digest(v['result']) and v['result']['result']==result
            and v['result']['native']['effect_status']=='COMMITTED_PROVEN' and v['result']['new_effect'] is False,'SIGNED_COHERENT_NATIVE_HISTORY')
    else:
        w=x['native_wait'];need(w['pid']==marker['pid'] and w['exit']==-9 and w['waited'] is True and w['pidfd_bound'] is True,'NATIVE_WAITED_SIGKILL')
        need(business['result'] is None and x['lost_reply']['error']=='NATIVE_EOF_NO_ACK','NATIVE_ROLLBACK_WITHOUT_ACK')
    return dict(profile=r['profile'],optimized=r['optimized'],case=case,deadline=d,marker_tick=marker['tick'],release_lower_bound=release,
        late_commit_counterexample=late,paired_schedule_rollback=not late,exact_commit_timestamp_claimed=False)
def run(a):
    files,identity=inputs(a);sources=json.loads(files['source-manifest.json']);manifest=json.loads(files['cells/MANIFEST.json'])
    need(manifest['sources']==sources and manifest['source_manifest_sha256']==SOURCE_SHA,'PARENT_CAPTURE_SOURCE_BINDING')
    primitive=Path(__file__).resolve().parent.parent/'native_admission_01/sources/crash/quiescence.py'
    need(digest(primitive.read_bytes())==sources['files']['crash/quiescence.py'],'PINNED_SIGNATURE_PRIMITIVE')
    spec=importlib.util.spec_from_file_location('c004_signature_primitives',primitive);q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
    rows=[];mutants=0
    for entry in manifest['cells']:
        r=json.loads(files['cells/'+entry['file']])
        if r['cut']!='before_commit' or r['execution_case'] not in ('expired_before_commit','expired_before_commit_kill'):continue
        rows.append(one(r,sources,q))
        changes=[lambda z:z['execution'].update(temporal_release_tick=z['execution']['issue']['response']['result']['result']['permit']['body']['not_after']-1),
            lambda z:z['execution']['issue']['response']['result']['result']['permit']['body']['allocation'].update(uid=62024)]
        if rows[-1]['late_commit_counterexample']:changes.append(lambda z:z['execution']['after_effect']['stores']['consumer.db' if z['profile']=='FCI' else 'resource.db']['c_permit_consumptions']['rows'].clear())
        else:changes.append(lambda z:z['execution']['native_wait'].update(waited=False))
        for f in changes:
            bad=copy.deepcopy(r);f(bad);need(bad!=r,'NATIVE_MUTATION_CHANGED')
            try:one(bad,sources,q)
            except Exception:mutants+=1
            else:raise ValueError('BAD_NATIVE_TEMPORAL_EVIDENCE_ACCEPTED')
    need(len(rows)==8 and sum(x['late_commit_counterexample'] for x in rows)==4 and mutants==24,'NATIVE_WITNESS_COUNTS')
    result=dict(status='PINNED_NATIVE_C004_WITNESSES_RECEIVED',parent_commit=COMMIT,parent_artifact=13979046352,parent_zip_sha256=PARENT_SHA,parent_content_inventory_sha256=TREE_SHA,
        input_verification=identity,native_new_execution=False,source_files_changed=False,native_late_commit_witnesses=4,native_paired_kill_rollbacks=4,evidence_mutations_rejected=mutants,
        C004_closed=False,physical_COMMIT_deadline_contract='COUNTEREXAMPLES_RECEIVED',assumptions='Original trusted supervisor, OS/clock, retained stores and no clones; no independent MAC audit or exact commit timestamp.',witnesses=rows)
    a.result.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:v for k,v in result.items() if k!='witnesses'}))
if __name__=='__main__':
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument('--parent-zip',type=Path);g.add_argument('--parent-dir',type=Path);p.add_argument('--result',type=Path,required=True);run(p.parse_args())
