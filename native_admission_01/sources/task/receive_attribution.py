"""Offline oracle: frozen refusal reader plus independent attribution binding."""
import argparse,copy,hashlib,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import receive
from shared import CASES,get,need
AUTH=b'GUARDED-PRODUCER-AUTH/1\0';EFFECT=b'GUARDED-PRODUCER-EFFECT/1\0'
PARTICIPANT='c86e4d661fbf87984d61e851cdd40710a8c9bbbb2032f815a2f579530094a6ba'
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()
def rows(c,profile):return c['diagnostic']['stores']['consumer.db' if profile=='FCI' else 'resource.db']['producer_results']['rows']
def one(r,w,verify):
    profile=r['profile'];case=r['case'];anchors=r['trust_anchors'];context=w['context'];base=w['request_B'];p=base['permit']['body']
    need(anchors==dict(issuer=context['issuer_public'],sink=context['sink_public']),'ROOT_PUBLIC_ANCHORS')
    auth=r['writer_ready']['producer_authorization'];a=verify(auth,anchors['issuer'],AUTH)
    need(a==dict(schema='GUARDED-PRODUCER-AUTH/1',profile=profile,invocation_id=a['invocation_id'],
        uid=62024,generation=2,request_digest=digest(base),key=context['key']) and type(a['invocation_id']) is str and len(a['invocation_id'])==32,'SIGNED_PRODUCER_AUTH')
    need(rows(r['while_paused'],profile)==[],'NO_EARLY_DURABLE_PRODUCER')
    side=rows(r['final'],profile)
    need(side==rows(r['after_guarded_writer'],profile),'NO_LATER_PRODUCER_WRITE')
    positive=case in ('COMMIT_FIRST','LOST_ACK_AFTER_COMMIT')
    if not positive:
        need(side==[] and r['final']['business']['native_effects']==[],'NO_EFFECT_NO_PRODUCER')
        return dict(profile=profile,case=case,producer_received=False,effect_count=0)
    need(len(side)==1 and len(r['final']['business']['native_effects'])==1,'ONE_EFFECT_ONE_PRODUCER')
    envelope=json.loads(side[0][2]);b=verify(envelope,anchors['sink'],EFFECT)
    legacy=r['final']['business']['business_results'][0];old=verify(legacy,anchors['sink'],b'SAME-K-NATIVE-BRIDGE-RESULT/1\0')
    participant=w['participant'];invocation=participant['invocation']
    need(hashlib.sha256((HERE/'participant.py').read_bytes()).hexdigest()==PARTICIPANT,'UNCHANGED_PARTICIPANT')
    need(participant['scope_restored'] is True and participant['restoration_failed'] is False
        and participant['request_digest']==digest(base) and participant['commit_boundary'] is True,'PARTICIPANT_COMMIT_SCOPE')
    need(b==dict(schema='GUARDED-PRODUCER-EFFECT/1',profile=profile,producer_invocation=a['invocation_id'],
        participant_invocation=invocation,participant_sha256=PARTICIPANT,uid=62024,generation=2,
        auth_digest=digest(auth),request_digest=digest(base),legacy_digest=digest(legacy),native_operation_id=p['native_operation_id'],
        effect_id=old['effect_id'],key=p['key'],content_hash=p['content_hash'],target=old['target'],old_version=old['old_version'],
        new_version=old['new_version'],value=old['value']),'EXACT_PRODUCER_PARTICIPANT_EFFECT')
    need(side[0][0]==json.dumps(p['key'],sort_keys=True,separators=(',',':'),ensure_ascii=True)
        and side[0][1]==a['invocation_id'],'SQL_PRODUCER_INDEX')
    return dict(profile=profile,case=case,producer_received=True,effect_count=1)
def run(a):
    sys.path.insert(0,str(a.support_root/'fci-same-k-handoff-20261030'))
    from handoff import verify
    original=receive.receive(a.folder,a.support_root,True)
    report=get(a.folder/'RESULTS.json');source=get(a.source_manifest)
    need(hashlib.sha256(a.source_manifest.read_bytes()).hexdigest()==a.source_manifest_sha256,'EXTERNAL_SOURCE_MANIFEST')
    need(all(report['copied_sources'][n]==h for n,h in source['files'].items() if n.endswith('.py') or n.startswith('native/') or n.startswith('support/')),'STAGED_SOURCE_BINDING')
    answers=[];rejected=[]
    for profile in ('FCI','STANDARD'):
      for case in CASES:
        p=a.folder/(profile+'__'+case);r=get(p/'report.json');w=get(p/'writer.json')
        answers.append(one(r,w,verify))
        for name,mutate in [('issuer_key',lambda x,y:x['trust_anchors'].update(issuer='00'*32)),
            ('auth_signature',lambda x,y:x['writer_ready']['producer_authorization'].update(signature='00'*64)),
            ('hidden_producer',lambda x,y:rows(x['final'],profile).append(['unbound','x','{}']))]:
            bad,other=copy.deepcopy((r,w));mutate(bad,other)
            try:one(bad,other,verify)
            except Exception:rejected.append(profile+'/'+case+'/'+name)
            else:raise ValueError('ATTRIBUTION_MUTANT_ACCEPTED:'+name)
        if case in ('COMMIT_FIRST','LOST_ACK_AFTER_COMMIT'):
            for field in ('participant_invocation','request_digest','producer_invocation','legacy_digest'):
                bad,other=copy.deepcopy((r,w));row=rows(bad['final'],profile)[0];env=json.loads(row[2]);env['body'][field]='0'*32;row[2]=json.dumps(env)
                try:one(bad,other,verify)
                except Exception:rejected.append(profile+'/'+case+'/'+field)
                else:raise ValueError('PRODUCER_MUTANT_ACCEPTED:'+field)
    need(not {'native_bridge','participant','attribution','sql_service','standard'}&set(sys.modules),'NO_NATIVE_OR_PRODUCER_IMPORT')
    result=dict(status='GUARDED_PRODUCER_20_RECEIVED',native_cells=20,optimized=report['optimized'],
        producer_effects=sum(x['effect_count'] for x in answers),results=answers,rejected_attribution_mutants=len(rejected),
        frozen_refusal_reader=original,source_manifest_sha256=a.source_manifest_sha256,
        authority_restored=False,recovery_authorized=False,full_no_bypass=False,independent_audit=False,M1='HOLD',SR02='BLOCKED')
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ('results','frozen_refusal_reader')}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('folder',type=Path)
    for n in ('support-root','source-manifest','out'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--source-manifest-sha256',required=True);run(p.parse_args())
