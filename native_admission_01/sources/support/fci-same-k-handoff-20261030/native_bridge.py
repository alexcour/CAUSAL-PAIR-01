"""Versioned research adapter: same-K ledger inside actual native SQL COMMITs.

Trusted in-process owner API. No native RPC/OS integration claim. Original
engine source files are imported unchanged from an explicitly pinned checkout.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from handoff import canonical, content_hash, key_text, public, signed, verify

PERMIT = b'SAME-K-NATIVE-BRIDGE-PERMIT/1\x00'
RESULT = b'SAME-K-NATIVE-BRIDGE-RESULT/1\x00'


def load_native(root):
    root = Path(root).resolve()
    sys.path.insert(0, str(root/'research/fci-sql-d2a-20261023'))
    sys.path.insert(0, str(root/'research/fci-d2a-standard-20261023'))
    from sql_service import SqlService
    from standard import Standard
    import authorization as auth
    return SqlService, Standard, auth


@contextmanager
def transaction(db):
    db.execute('BEGIN IMMEDIATE')
    try:
        yield
        db.commit()
    except BaseException:
        if db.in_transaction:db.rollback()
        raise


def provision_ledger(db, policy):
    # Offline provisioning only. Constructor never creates, migrates or resets.
    db.executescript('''
      CREATE TABLE sk_control(id INTEGER PRIMARY KEY CHECK(id=1),schema TEXT NOT NULL,policy TEXT NOT NULL,epoch INTEGER NOT NULL,revoked INTEGER NOT NULL);
      CREATE TABLE sk_business(k TEXT PRIMARY KEY,content TEXT NOT NULL,h TEXT NOT NULL,result TEXT);
      CREATE TABLE sk_attempts(k TEXT NOT NULL,g INTEGER NOT NULL,attempt_id TEXT UNIQUE NOT NULL,uid INTEGER NOT NULL,rid TEXT UNIQUE NOT NULL,state TEXT NOT NULL,PRIMARY KEY(k,g));
      CREATE UNIQUE INDEX sk_one_open ON sk_attempts(k) WHERE state='OPEN';
      CREATE TABLE sk_readers(k TEXT NOT NULL,uid INTEGER NOT NULL,PRIMARY KEY(k,uid));
    ''')
    db.execute("INSERT INTO sk_control VALUES(1,'SAME-K-NATIVE-BRIDGE/1',?,1,0)",(policy,));db.commit()


class NativeBridge:
    def __init__(self, root, runtime, profile, signer, sink_key, *, requester=62023,
                 successor=62024, controller=62022, now=None, fault=lambda _:None):
        SqlService, Standard, self.auth = load_native(root)
        self.profile=profile;self.runtime=Path(runtime);self.signer=signer;self.sink_key=sink_key
        self.requesters={requester,successor};self.controller=controller
        self.now=now or (lambda:int(time.monotonic()));self.fault=fault
        self.active=None;self.guard_observations=[]
        bridge=self

        class FCIAdapter(SqlService):
            def execute(self, uid, req):
                bridge.require(bridge.active is not None and uid in bridge.requesters,'BRIDGE_CONTEXT_REQUIRED')
                return super().execute(uid,req)

            def capture(self, kind, data, raw, service):
                is_effect=kind=='tx_stage' and data.get('operation')=='finish' and raw.get('result_new_effect')
                before=None
                if is_effect:
                    bridge.require(bridge.active is not None,'BRIDGE_CONTEXT_REQUIRED')
                    before=bridge.admit(service.consumer.db,*bridge.active)
                super().capture(kind,data,raw,service)
                if is_effect:
                    bridge.finish(service.consumer.db,*bridge.active,before)
                    bridge.fault('before_commit')
                if kind=='tx_commit' and data.get('operation')=='finish':bridge.fault('after_commit')

        class StandardAdapter(Standard):
            def execute(self, uid, req):
                bridge.require(bridge.active is not None and uid in bridge.requesters,'BRIDGE_CONTEXT_REQUIRED')
                return super().execute(uid,req)

        if profile=='FCI':
            self.engine=FCIAdapter(self.runtime,journal=self.runtime/'native-journal.jsonl')
            # Explicit adapter policy extension, not a change of the real subject.
            self.engine.roles[successor]='requester'
            self.db=self.engine.consumer.db
            self.table='demo_configuration';self.effects='demo_effects'
            self.policy=self.engine.policy.digest
        elif profile=='STANDARD':
            self.engine=StandardAdapter(self.runtime,lambda:dict(flags=[True]*5,source_ok=True),hook=self.standard_hook)
            self.db=self.engine.db;self.table='configuration';self.effects='effects'
            self.policy=self.engine.cfg['policy_digest']
        else:raise ValueError('PROFILE')
        self.path=next(r[2] for r in self.db.execute('PRAGMA database_list') if r[1]=='main')
        self.require(self.db.execute('SELECT schema,policy FROM sk_control WHERE id=1').fetchone()==('SAME-K-NATIVE-BRIDGE/1',self.policy),'LEDGER_CONFIG')
        self.pending_before=None

    def require(self, condition, reason):
        self.auth.require(condition,reason)

    @contextmanager
    def open_control(self):
        db=sqlite3.connect('file:'+self.path+'?mode=rw',uri=True,isolation_level=None,timeout=10)
        db.execute('PRAGMA synchronous=FULL')
        try:yield db
        finally:db.close()

    def control(self, db):
        row=db.execute('SELECT policy,epoch,revoked FROM sk_control WHERE id=1').fetchone()
        self.require(row is not None,'CONTROL_MISSING');return row

    def latest(self, db, k):
        return db.execute('SELECT g,attempt_id,uid,rid,state FROM sk_attempts WHERE k=? ORDER BY g DESC LIMIT 1',(k,)).fetchone()

    def bind(self, k, content, actor):
        self.require(actor==self.controller,'CONTROL_ROLE');kt=key_text(k);h=content_hash(content)
        self.require(k['sink']==self.profile and k['deployment']==self.deployment,'SINK_DEPLOYMENT')
        with self.open_control() as db,transaction(db):
            row=db.execute('SELECT content,h FROM sk_business WHERE k=?',(kt,)).fetchone()
            if row:self.require(row==(canonical(content).decode(),h),'CONTENT_CONFLICT')
            else:db.execute('INSERT INTO sk_business VALUES(?,?,?,NULL)',(kt,canonical(content).decode(),h))
        return h

    @property
    def deployment(self):
        return self.engine.meta()['deployment_id'] if self.profile=='FCI' else self.engine.cfg['deployment_id']

    def business(self, db, kt, h):
        row=db.execute('SELECT content,h,result FROM sk_business WHERE k=?',(kt,)).fetchone()
        self.require(row is not None and row[1]==h,'CONTENT_CONFLICT');return row

    def no_unrecorded_effect(self, db, kt):
        found=db.execute('SELECT 1 FROM '+self.effects+' e JOIN sk_attempts a ON e.operation_id=a.rid WHERE a.k=? LIMIT 1',(kt,)).fetchone()
        self.require(found is None,'NATIVE_EFFECT_WITHOUT_RESULT')

    def assign(self, k, h, expected, uid, actor):
        self.require(actor==self.controller and uid in self.requesters,'CONTROL_ROLE')
        kt=key_text(k)
        with self.open_control() as db,transaction(db):
            row=self.business(db,kt,h);old=self.latest(db,kt)
            self.require(row[2] is None,'RESULT_ALREADY_COMMITTED')
            self.no_unrecorded_effect(db,kt)
            self.require((old[0] if old else 0)==expected and (old is None or old[4]=='FENCED'),'ATTEMPT_STILL_OPEN')
            g=expected+1;attempt=uuid.uuid4().hex
            rid=hashlib.sha256(b'SAME-K-NATIVE-ATTEMPT/1\x00'+canonical([k,h,g,attempt,uid])).hexdigest()
            db.execute("INSERT INTO sk_attempts VALUES(?,?,?,?,?,'OPEN')",(kt,g,attempt,uid,rid))
            db.execute('INSERT OR IGNORE INTO sk_readers VALUES(?,?)',(kt,uid))
        return dict(key=k,h=h,generation=g,attempt_id=attempt,uid=uid,rid=rid)

    def issue(self, allocation, actor, ttl=25):
        self.require(actor==self.controller,'CONTROL_ROLE');a=allocation
        kt=key_text(a['key'])
        with self.open_control() as db:
            row=self.business(db,kt,a['h']);p,epoch,revoked=self.control(db)
            self.require(self.latest(db,kt)==(a['generation'],a['attempt_id'],a['uid'],a['rid'],'OPEN') and row[2] is None and not revoked,'STALE_ALLOCATION')
        c=json.loads(row[0]);auth=self.auth
        native_epoch=self.engine.meta()['epoch'] if self.profile=='FCI' else self.engine.control()[0]
        context=__import__('fci_hardened.service',fromlist=['CONTEXT']).CONTEXT if self.profile=='FCI' else self.engine.cfg['context']
        real=int(time.monotonic())
        body=dict(schema=auth.SCHEMA,key_id=auth.KEY_ID,namespace=auth.NAMESPACE,deployment_id=self.deployment,
                  operation_id=a['rid'],target=c['target'],action=c['action'],expected_version=c['expected_version'],value=c['value'],
                  subject_uid=a['uid'],subject_role='requester',policy_digest=self.policy,context=context,
                  authority_epoch=native_epoch,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),not_before=real,not_after=real+30)
        env=signed(self.signer,auth.DOMAIN,body)
        native=dict(op='execute',operation={f:body[f] for f in auth.OP_FIELDS},authorization=env)
        now=self.now();self.require(type(ttl) is int and 0<ttl<=30,'VALIDITY')
        permit=signed(self.sink_key,PERMIT,dict(schema='BRIDGE-PERMIT/1',key=a['key'],content_hash=a['h'],generation=a['generation'],attempt_id=a['attempt_id'],subject_uid=a['uid'],native_operation_id=a['rid'],native_digest=hashlib.sha256(canonical(native)).hexdigest(),policy=p,epoch=epoch,not_before=now,not_after=now+ttl))
        return dict(permit=permit,native=native)

    def check(self, db, request, uid):
        self.auth.exact_shape(request,('permit','native'))
        b=verify(request['permit'],public(self.sink_key),PERMIT)
        self.auth.exact_shape(b,('schema','key','content_hash','generation','attempt_id','subject_uid','native_operation_id','native_digest','policy','epoch','not_before','not_after'))
        self.require(b['schema']=='BRIDGE-PERMIT/1' and type(uid) is int and uid in self.requesters and uid==b['subject_uid'],'BRIDGE_SUBJECT')
        kt=key_text(b['key']);row=self.business(db,kt,b['content_hash']);native=request['native']
        self.require(hashlib.sha256(canonical(native)).hexdigest()==b['native_digest'],'NATIVE_DIGEST')
        nb=native['authorization']['body'];c=json.loads(row[0])
        self.require(nb['operation_id']==b['native_operation_id'] and nb['subject_uid']==uid and all(nb[f]==c[f] for f in ('target','action','expected_version','value')),'NATIVE_BUSINESS_BINDING')
        self.require(b['key']['sink']==self.profile and b['key']['deployment']==self.deployment,'SINK_DEPLOYMENT')
        cur=self.latest(db,kt)
        self.require(cur is not None and cur[:4]==(b['generation'],b['attempt_id'],uid,b['native_operation_id']) and cur[4] in ('OPEN','APPLIED'),'STALE_ATTEMPT')
        p,epoch,revoked=self.control(db)
        self.require(not revoked and b['epoch']==epoch and b['policy']==p==self.policy,'BRIDGE_REVOKED')
        now=self.now();self.guard_observations.append(dict(now=now,in_transaction=db.in_transaction,generation=cur[0]))
        self.require(type(now) is int and type(b['not_before']) is int and type(b['not_after']) is int and b['not_before']<=now<b['not_after']<=b['not_before']+30,'BRIDGE_EXPIRED')
        return kt,row,b

    def admit(self, db, request, uid):
        self.require(db.in_transaction,'NO_NATIVE_TRANSACTION')
        self.guard_observations.append(dict(stage='native_admission',now=None,in_transaction=True,generation=request['permit']['body']['generation']))
        kt,row,b=self.check(db,request,uid)
        self.require(row[2] is None and self.latest(db,kt)[4]=='OPEN','RESULT_ALREADY_COMMITTED')
        self.no_unrecorded_effect(db,kt)
        c=json.loads(row[0])
        old=db.execute('SELECT value,version FROM '+self.table+' WHERE target=?',(c['target'],)).fetchone()
        self.require(old is not None and old[1]==c['expected_version'],'SQL_PRECONDITION')
        return old

    def finish(self, db, request, uid, before):
        self.require(db.in_transaction,'NO_NATIVE_TRANSACTION')
        b=request['permit']['body'];kt=key_text(b['key'])
        c=json.loads(self.business(db,kt,b['content_hash'])[0])
        native=db.execute('SELECT old_version,new_version,value FROM '+self.effects+' WHERE operation_id=?',(b['native_operation_id'],)).fetchall()
        self.require(native==[(before[1],before[1]+1,c['value'])],'NATIVE_EFFECT_MISSING')
        result=signed(self.sink_key,RESULT,dict(schema='BRIDGE-RESULT/1',key=b['key'],content_hash=b['content_hash'],generation=b['generation'],subject_uid=uid,native_operation_id=b['native_operation_id'],effect_id=uuid.uuid4().hex,target=c['target'],old_value=before[0],value=c['value'],old_version=before[1],new_version=before[1]+1,sink_public=public(self.sink_key)))
        db.execute('UPDATE sk_business SET result=? WHERE k=? AND result IS NULL',(canonical(result).decode(),kt))
        db.execute("UPDATE sk_attempts SET state='APPLIED' WHERE k=? AND g=?",(kt,b['generation']))

    def standard_hook(self, point):
        if point=='after_final_sample':
            self.require(self.active is not None,'BRIDGE_CONTEXT_REQUIRED')
            self.pending_before=self.admit(self.engine.db,*self.active)
        elif point=='after_sql_staging':
            self.finish(self.engine.db,*self.active,self.pending_before);self.fault('before_commit')
        elif point=='after_commit':self.fault('after_commit')

    def execute(self, request, uid, *, after_precheck=lambda:None):
        # after_precheck is trusted test instrumentation, never a wire field.
        with self.open_control() as db:
            kt,row,_=self.check(db,request,uid)
            if row[2] is not None:return dict(status='RECOVERED',result=self.read_result(request['permit']['body']['key'],request['permit']['body']['content_hash'],uid))
        after_precheck();self.active=(request,uid)
        try:
            raw=self.engine.execute(uid,request['native'])
        finally:self.active=None
        with self.open_control() as db:
            result=self.business(db,kt,request['permit']['body']['content_hash'])[2]
        if result is not None and raw.get('new_effect') is True:return dict(status='NEW',result=json.loads(result),native=raw)
        return dict(status='HOLD_NATIVE',native=raw)

    def resolve(self, k, h, generation, actor):
        self.require(actor==self.controller,'CONTROL_ROLE');kt=key_text(k)
        with self.open_control() as db,transaction(db):
            row=self.business(db,kt,h);cur=self.latest(db,kt)
            self.require(cur is not None and cur[0]==generation,'STALE_ATTEMPT')
            if row[2] is not None:return dict(disposition='RESULT_RETRIEVED',result=json.loads(row[2]))
            self.no_unrecorded_effect(db,kt)
            self.require(cur[4] in ('OPEN','FENCED'),'RESULT_INCONSISTENT')
            db.execute("UPDATE sk_attempts SET state='FENCED' WHERE k=? AND g=?",(kt,generation))
            return dict(disposition='NONEXECUTION_FENCED')

    def grant_read(self, k, h, uid, actor):
        self.require(actor==self.controller and uid in self.requesters,'CONTROL_ROLE');kt=key_text(k)
        with self.open_control() as db,transaction(db):
            self.business(db,kt,h);db.execute('INSERT OR IGNORE INTO sk_readers VALUES(?,?)',(kt,uid))

    def read_result(self, k, h, uid):
        kt=key_text(k)
        with self.open_control() as db,transaction(db):
            row=self.business(db,kt,h)
            self.require(uid==self.controller or db.execute('SELECT 1 FROM sk_readers WHERE k=? AND uid=?',(kt,uid)).fetchone(),'READ_ROLE')
            self.require(row[2] is not None,'RESULT_NOT_AVAILABLE')
            result=json.loads(row[2]);b=verify(result,public(self.sink_key),RESULT)
            self.require(b['key']==k and b['content_hash']==h,'RESULT_BINDING')
            cur=self.latest(db,kt)
            self.require(cur is not None and cur[0]==b['generation'] and cur[2:]==(b['subject_uid'],b['native_operation_id'],'APPLIED'),'RESULT_INCONSISTENT')
            native=db.execute('SELECT old_version,new_version,value FROM '+self.effects+' WHERE operation_id=?',(b['native_operation_id'],)).fetchall()
            self.require(native==[(b['old_version'],b['new_version'],b['value'])],'RESULT_INCONSISTENT')
            return result

    def revoke(self, actor):
        self.require(actor==self.controller,'CONTROL_ROLE')
        with self.open_control() as db,transaction(db):db.execute('UPDATE sk_control SET revoked=1,epoch=epoch+1 WHERE id=1')

    def close(self):self.engine.close()
