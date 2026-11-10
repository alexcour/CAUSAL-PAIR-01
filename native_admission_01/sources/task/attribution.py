"""Additive SQL component; keeps pinned guard methods and participant unchanged."""
import hashlib,json,uuid
from pathlib import Path
from handoff import canonical,public,signed,verify,key_text

AUTH=b'GUARDED-PRODUCER-AUTH/1\0'
EFFECT=b'GUARDED-PRODUCER-EFFECT/1\0'
PARTICIPANT='c86e4d661fbf87984d61e851cdd40710a8c9bbbb2032f815a2f579530094a6ba'
def digest(x):return hashlib.sha256(canonical(x)).hexdigest()
def need(ok,reason):
    if not ok:raise ValueError(reason)
def auth_body(base,profile,invocation):
    p=base['permit']['body']
    return dict(schema='GUARDED-PRODUCER-AUTH/1',profile=profile,invocation_id=invocation,
        uid=p['subject_uid'],generation=p['generation'],request_digest=digest(base),key=p['key'])
def effect_body(base,auth,legacy,profile,invocation):
    a=auth['body'];p=base['permit']['body'];r=legacy['body']
    return dict(schema='GUARDED-PRODUCER-EFFECT/1',profile=profile,producer_invocation=a['invocation_id'],
        participant_invocation=invocation,participant_sha256=PARTICIPANT,uid=p['subject_uid'],generation=p['generation'],
        auth_digest=digest(auth),request_digest=digest(base),legacy_digest=digest(legacy),
        native_operation_id=p['native_operation_id'],effect_id=r['effect_id'],key=p['key'],content_hash=p['content_hash'],
        target=r['target'],old_version=r['old_version'],new_version=r['new_version'],value=r['value'])
def check(env,auth,base,legacy,profile,invocation,issuer,sink):
    a=verify(auth,issuer,AUTH)
    need(a==auth_body(base,profile,a['invocation_id']) and len(a['invocation_id'])==32
        and a['uid']==62024 and type(a['uid']) is int and a['generation']==2,'PRODUCER_AUTH_BINDING')
    body=verify(env,sink,EFFECT)
    from native_bridge import RESULT
    old=verify(legacy,sink,RESULT);p=base['permit']['body']
    need(old['key']==p['key'] and old['content_hash']==p['content_hash'] and old['subject_uid']==62024
        and old['generation']==2 and old['native_operation_id']==p['native_operation_id'],'LEGACY_BINDING')
    need(body==effect_body(base,auth,legacy,profile,invocation),'PARTICIPANT_PRODUCER_EFFECT_BINDING')
    need(type(invocation) is str and len(invocation)==32,'PARTICIPANT_INVOCATION')
    return body
def augment(Base):
    class AttributedBridge(Base):
        def __init__(self,*a,**kw):
            super().__init__(*a,**kw)
            # Declared fixture schema provisioning, before any protected B invocation.
            with self.open_control() as db:
                db.execute('CREATE TABLE producer_results(k TEXT PRIMARY KEY,invocation_id TEXT UNIQUE NOT NULL,envelope TEXT NOT NULL)')
                db.commit()
            import retirement
            retirement.provision(Path(self.path))
            import admission
            admission.provision(Path(self.path))
            self.producer_participant=None
        def prepare_attribution(self,request,uid):
            need(uid==62024 and request['permit']['body']['subject_uid']==uid,'PRODUCER_SUBJECT')
            self.producer_authorization=signed(self.signer,AUTH,auth_body(request,self.profile,uuid.uuid4().hex))
        def finish(self,db,request,uid,before):
            need(db is self.db and db.in_transaction and self.producer_participant is not None,'GUARDED_TRANSACTION')
            need(self.producer_participant.b is self and self.producer_participant.request_digest==digest(request)
                and self.producer_participant.uid==uid==62024,'ACTIVE_PARTICIPANT_BINDING')
            need(hashlib.sha256(Path(__file__).with_name('participant.py').read_bytes()).hexdigest()==PARTICIPANT,'PINNED_PARTICIPANT')
            super().finish(db,request,uid,before)
            kt=key_text(request['permit']['body']['key'])
            legacy=json.loads(db.execute('SELECT result FROM sk_business WHERE k=?',(kt,)).fetchone()[0])
            body=effect_body(request,self.producer_authorization,legacy,self.profile,self.producer_participant.invocation)
            envelope=signed(self.sink_key,EFFECT,body)
            check(envelope,self.producer_authorization,request,legacy,self.profile,self.producer_participant.invocation,public(self.signer),public(self.sink_key))
            db.execute('INSERT INTO producer_results VALUES(?,?,?)',(kt,body['producer_invocation'],canonical(envelope).decode()))
            need(db.in_transaction,'SAME_NATIVE_TRANSACTION')
    return AttributedBridge
