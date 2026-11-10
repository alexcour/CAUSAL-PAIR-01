"""Versioned trusted-supervisor decision gate. Never executes, rearms or writes SQL.

The context/pin MUST come from the root-owned launcher path, never RPC input.
Root/OS/collector are trusted; absence of live clones remains an explicit assumption.
"""
import hashlib,json,os,stat,re
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
DOMAIN=b'FCI-TERMINATED-OWNER/2\0'
DECISION=b'FCI-QUIESCENCE-DECISION/2\0'
PARTICIPANT='c86e4d661fbf87984d61e851cdd40710a8c9bbbb2032f815a2f579530094a6ba'
def need(x,code):
    if not x:raise ValueError(code)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def digest(x):return hashlib.sha256(canonical(x)).hexdigest()
def policy_hash():return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
def verify(e,pin,domain):
    need(type(e) is dict and set(e)=={'body','signature'},'SIGNED_SHAPE')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin)).verify(bytes.fromhex(e['signature']),domain+canonical(e['body']));return e['body']
def signed(key,domain,body):return dict(body=body,signature=key.sign(domain+canonical(body)).hex())
def authority_names(profile):
    need(profile in ('FCI','STANDARD'),'PROFILE')
    return ['consumer.db','spend.db','anchor.db','replica.db'] if profile=='FCI' else ['resource.db','reference.db']
def inventory(runtime,profile):
    out={}
    for name in authority_names(profile):
        p=Path(runtime)/name
        if not p.is_file():continue
        s=p.stat();out[name]=dict(dev=s.st_dev,inode=s.st_ino,uid=s.st_uid,mode=stat.S_IMODE(s.st_mode),sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    return out
def load_context(path):
    path=Path(path)
    for p in (path,path.parent):
        s=p.stat();need(s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTEXT_BOUNDARY')
    context=json.loads(path.read_text());proof_path=path.with_name('proof.json')
    if not proof_path.exists():return context,None
    s=proof_path.stat();need(s.st_uid==0 and not s.st_mode&0o022,'ROOT_PROOF_BOUNDARY')
    return context,json.loads(proof_path.read_text())
def scope(prepared):
    base=prepared['request_B'];p=base['permit']['body']
    return dict(profile=p['key']['sink'],key=p['key'],content_hash=p['content_hash'],generation=2,uid=62024,
        native_operation_id=p['native_operation_id'],request_digest=digest(base),producer_auth_digest=digest(prepared['producer_authorization']))
def make_context(prepared,public_key,birth,proof_id,supervisor_pid):
    return dict(schema='FCI-QUIESCENCE-CONTEXT/2',scope=scope(prepared),birth=birth,proof_id=proof_id,
        supervisor_public=public_key,supervisor_pid=supervisor_pid,supervisor_uid=0,policy_sha256=policy_hash(),
        issuer_public=prepared['context']['issuer_public'],sink_public=prepared['context']['sink_public'],no_live_clones_assumed=True)
def make_proof(context,wait,stores,files):
    return dict(schema='FCI-TERMINATED-OWNER/2',proof_id=context['proof_id'],scope=context['scope'],birth=context['birth'],
        supervisor_pid=context['supervisor_pid'],supervisor_uid=0,policy_sha256=context['policy_sha256'],wait=wait,
        no_live_clones_assumed=True,authority_inventory=files,state_digest=digest(stores))
def quiescence(context,proof,prepared):
    need(context['schema']=='FCI-QUIESCENCE-CONTEXT/2' and context['policy_sha256']==policy_hash()
        and context['scope']==scope(prepared),'EXPECTED_SCOPE_AND_POLICY')
    need(context['issuer_public']==prepared['context']['issuer_public'] and context['sink_public']==prepared['context']['sink_public'],'EXPECTED_EFFECT_KEYS')
    need(context['no_live_clones_assumed'] is True and type(context['supervisor_uid']) is int and context['supervisor_uid']==0
        and type(context['supervisor_pid']) is int and context['supervisor_pid']>0
        and type(context['proof_id']) is str and re.fullmatch('[0-9a-f]{32}',context['proof_id']) is not None,'TRUSTED_SUPERVISOR_SCOPE')
    b=verify(proof,context['supervisor_public'],DOMAIN)
    expected={k:context[k] for k in ('proof_id','scope','birth','supervisor_pid','supervisor_uid','policy_sha256','no_live_clones_assumed')}
    need(set(b)=={'schema',*expected,'wait','authority_inventory','state_digest'} and b['schema']=='FCI-TERMINATED-OWNER/2'
        and all(b[k]==v for k,v in expected.items()),'EXACT_TERMINATION_BINDING')
    birth=b['birth'];need(set(birth)=={'pid','uid','boot_id','start_ticks'} and type(birth['pid']) is int and birth['pid']>0
        and type(birth['uid']) is int and birth['uid']==62021 and type(birth['start_ticks']) is int and birth['start_ticks']>0
        and type(birth['boot_id']) is str and len(birth['boot_id'])==36
        and birth['boot_id']==prepared['request_B']['native']['authorization']['body']['boot_id'],'PROCESS_BIRTH_BINDING')
    need(b['wait']==dict(method='Popen.wait/waitpid',returncode=-9,signal=9,pidfd_bound=True,pidfd_ready=True),'KERNEL_BOUND_SIGKILL_WAIT')
    need(type(b['wait']['returncode']) is type(b['wait']['signal']) is int
        and b['wait']['pidfd_bound'] is b['wait']['pidfd_ready'] is True,'EXACT_WAIT_TYPES')
    names=authority_names(context['scope']['profile'])
    need(set(b['authority_inventory'])==set(names),'COMPLETE_ATTESTED_AUTHORITY')
    for entry in b['authority_inventory'].values():
        need(set(entry)=={'dev','inode','uid','mode','sha256'} and all(type(entry[k]) is int and entry[k]>=0 for k in ('dev','inode','uid','mode'))
            and entry['inode']>0 and entry['uid']==62021 and not entry['mode']&0o022
            and type(entry['sha256']) is str and re.fullmatch('[0-9a-f]{64}',entry['sha256']) is not None,'AUTHORITY_DESCRIPTOR')
    need(type(b['state_digest']) is str and re.fullmatch('[0-9a-f]{64}',b['state_digest']) is not None,'ATTESTED_VIEW_DIGEST')
    return b
def rows(stores,store,table):
    t=stores[store][table];return [dict(zip(t['columns'],r)) for r in t['rows']]
def outcome(context,prepared,stores):
    """Authenticate historical result or report native B unresolved; never absence proof."""
    p=prepared['request_B']['permit']['body'];base=prepared['request_B'];c=prepared['context'];profile=p['key']['sink'];main=authority_names(profile)[0]
    need(context['scope']==scope(prepared),'OUTCOME_SCOPE')
    cert=verify(c['certificate'],context['sink_public'],b'FCI-NATIVE-NONEXECUTION-CERTIFICATE/1\0')
    permit=verify(base['permit'],context['sink_public'],b'SAME-K-NATIVE-BRIDGE-PERMIT/1\0')
    native=verify(base['native']['authorization'],context['issuer_public'],b'FCI-SQL-D2A-AUTHZ/1\0')
    auth=prepared['producer_authorization'];a=verify(auth,context['issuer_public'],b'GUARDED-PRODUCER-AUTH/1\0')
    need(cert['fenced_generation']==1 and cert['key']==p['key'] and cert['content_hash']==p['content_hash'] and cert['successor_uid']==62024,'PREDECESSOR_CERTIFICATE')
    need(permit==p and p['generation']==2 and p['subject_uid']==native['subject_uid']==62024
        and p['native_operation_id']==native['operation_id'] and p['native_digest']==digest(base['native']),'SIGNED_REQUEST_BINDING')
    need(a==dict(schema='GUARDED-PRODUCER-AUTH/1',profile=profile,invocation_id=a['invocation_id'],uid=62024,generation=2,
        request_digest=digest(base),key=p['key']) and type(a['invocation_id']) is str and len(a['invocation_id'])==32,'SIGNED_PRODUCER_AUTH')
    attempts=rows(stores,main,'sk_attempts');need(len(attempts)==2,'TWO_GENERATIONS_ONLY')
    aa=next(x for x in attempts if x['g']==1);bb=next(x for x in attempts if x['g']==2)
    kt=canonical(p['key']).decode()
    need(aa['k']==bb['k']==kt and aa['rid']==cert['fenced_native_operation_id'] and aa['state']=='FENCED'
        and bb['rid']==p['native_operation_id'] and bb['attempt_id']==p['attempt_id'] and bb['uid']==62024,'CURRENT_ATTEMPTS')
    business=rows(stores,main,'sk_business');need(len(business)==1 and business[0]['k']==kt and business[0]['h']==p['content_hash'],'BUSINESS_BINDING')
    content=json.loads(business[0]['content']);need(hashlib.sha256(b'FCI-SAME-K-CONTENT/1\0'+canonical(content)).hexdigest()==p['content_hash'],'CONTENT_HASH')
    certificates=rows(stores,main,'sk_certificates');need(len(certificates)==1 and json.loads(certificates[0]['envelope'])==c['certificate']
        and certificates[0]['redeemed']==1 and json.loads(certificates[0]['allocation'])==c['allocation_B'],'RETAINED_PREDECESSOR_HANDOFF')
    nt=rows(stores,main,'d2_operations') if profile=='FCI' else rows(stores,'reference.db','attempts')
    need(len(nt)==2 and {x['operation_id'] for x in nt}=={aa['rid'],bb['rid']},'NATIVE_A_B_RECORDS')
    nb=next(x for x in nt if x['operation_id']==bb['rid']);envelope=json.loads(nb['envelope'])
    need(envelope==base['native']['authorization'] and nb['authorization_digest' if profile=='FCI' else 'digest']==hashlib.sha256(b'FCI-SQL-D2A-AUTHZ/1\0'+canonical(envelope['body'])).hexdigest(),'NATIVE_B_ENVELOPE')
    effects=rows(stores,main,'demo_effects' if profile=='FCI' else 'effects');producers=rows(stores,main,'producer_results')
    configurations=rows(stores,main,'demo_configuration' if profile=='FCI' else 'configuration')
    target=next(x for x in configurations if x['target']==content['target'])
    if business[0]['result'] is None:
        need(effects==producers==[] and bb['state']=='OPEN' and target['version']==content['expected_version']
            and nb['phase']==('PREPARED' if profile=='FCI' else 'RESERVED'),'UNRESOLVED_NATIVE_B_VIEW')
        return dict(status='NATIVE_B_UNRESOLVED',native_phase=nb['phase'],historical_result_verified=False,producer_digest=None)
    need(len(effects)==len(producers)==1 and bb['state']=='APPLIED','ONE_APPLIED_EFFECT')
    legacy=json.loads(business[0]['result']);old=verify(legacy,context['sink_public'],b'SAME-K-NATIVE-BRIDGE-RESULT/1\0')
    producer=json.loads(producers[0]['envelope']);body=verify(producer,context['sink_public'],b'GUARDED-PRODUCER-EFFECT/1\0')
    need(old['key']==p['key'] and old['content_hash']==p['content_hash'] and old['generation']==2 and old['subject_uid']==62024
        and old['native_operation_id']==p['native_operation_id'],'SIGNED_RESULT_BINDING')
    invocation=body['participant_invocation'];need(type(invocation) is str and len(invocation)==32,'PARTICIPANT_INVOCATION')
    need(body==dict(schema='GUARDED-PRODUCER-EFFECT/1',profile=profile,producer_invocation=a['invocation_id'],participant_invocation=invocation,
        participant_sha256=PARTICIPANT,uid=62024,generation=2,auth_digest=digest(auth),request_digest=digest(base),legacy_digest=digest(legacy),
        native_operation_id=p['native_operation_id'],effect_id=old['effect_id'],key=p['key'],content_hash=p['content_hash'],target=old['target'],
        old_version=old['old_version'],new_version=old['new_version'],value=old['value']),'EXACT_PRODUCER_RESULT_BINDING')
    effect=effects[0];need(effect['operation_id']==bb['rid'] and effect['old_version']==content['expected_version'] and
        effect['new_version']==target['version']==content['expected_version']+1 and effect['value']==target['value']==content['value'],'NATIVE_EFFECT_READBACK')
    need(nb['phase']=='COMMITTED' if profile=='FCI' else nb['phase'] in ('RESERVED','COMMITTED'),'HISTORICAL_NATIVE_PHASE')
    return dict(status='RESULT_VERIFIED',native_phase=nb['phase'],historical_result_verified=True,producer_digest=digest(producer))
def decide(context,proof,prepared,stores,files):
    result=dict(schema='FCI-QUIESCENCE-GATE/2',quiescence='UNATTESTED',authority='UNVERIFIED',outcome='UNKNOWN',
        historical_result_verified=False,native_phase=None,producer_digest=None,decision='HOLD',code=None,
        new_execution=False,execution_authorized=False,recovery_authorized=False,independent_audit=False)
    if not context.get('supervisor_public'):
        result['code']='LEGACY_SUPERVISION_UNBOUND'
        try:
            found=outcome(context,prepared,stores)
            result.update(outcome=found['status'],historical_result_verified=found['historical_result_verified'],native_phase=found['native_phase'],producer_digest=found['producer_digest'])
        except Exception:pass
        return result
    if proof is None:result['code']='SUPERVISOR_PROOF_UNAVAILABLE';return result
    try:b=quiescence(context,proof,prepared)
    except Exception:result['code']='TERMINATION_ATTESTATION_INVALID';return result
    result['quiescence']='ATTESTED_TERMINATED_OWNER'
    names=authority_names(context['scope']['profile'])
    if stores is None or set(files)!=set(names):
        result.update(authority='UNAVAILABLE',code='AUTHORITY_FILE_UNAVAILABLE');return result
    if files!=b['authority_inventory'] or digest(stores)!=b['state_digest']:
        result.update(authority='MISMATCH',code='AUTHORITY_VIEW_CHANGED');return result
    result['authority']='RETAINED_VIEW_VERIFIED'
    try:found=outcome(context,prepared,stores)
    except Exception:result['code']='NATIVE_VIEW_INCONSISTENT';return result
    result.update(outcome=found['status'],historical_result_verified=found['historical_result_verified'],native_phase=found['native_phase'],producer_digest=found['producer_digest'])
    if found['status']=='RESULT_VERIFIED':result.update(decision='HISTORICAL_RESULT_ONLY',code='RESULT_RETRIEVED_NO_REEXECUTION')
    else:result['code']='NATIVE_B_UNRESOLVED'
    return result
