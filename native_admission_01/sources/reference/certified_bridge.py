"""Retained native-authority API: fence+outcome certificate in one SQL txn.

This is a new versioned composition, not a release of an external SEALED slot.
It assumes the real native effect/ledger/certificate DB is retained, all writes
are mediated, and the trusted executor/OS has no cloned live continuation.
"""
import hashlib
import json
import sqlite3
import uuid

from native_bridge import NativeBridge, transaction
from handoff import canonical, key_text, public, signed, verify

DOMAIN=b'FCI-NATIVE-NONEXECUTION-CERTIFICATE/1\x00'
FIELDS=('schema','certificate_id','key','content_hash','sink_public','policy',
        'fenced_generation','fenced_attempt_id','fenced_native_operation_id',
        'fenced_subject_uid','successor_uid','epoch_at_fence','disposition')


class CertifiedBridge(NativeBridge):
    def __init__(self,*args,initialize=False,certificate_fault=lambda _:None,
                 certificate_trace=lambda _:None,**kwargs):
        super().__init__(*args,**kwargs)
        self.certificate_fault=certificate_fault
        self.certificate_trace=certificate_trace
        # Cache on the owner thread; a control-connection thread never touches
        # the native engine's SQLite connection.
        self.certificate_deployment=self.deployment
        with self.open_control() as db,transaction(db):
            if initialize:
                self.require(not db.execute("SELECT 1 FROM sqlite_master WHERE name='sk_certificates'").fetchone(),
                             'CERTIFICATE_STORE_ALREADY_EXISTS')
                db.execute('''CREATE TABLE sk_certificates(
                    id TEXT PRIMARY KEY,k TEXT NOT NULL,g INTEGER NOT NULL,h TEXT NOT NULL,
                    envelope TEXT NOT NULL,redeemed INTEGER NOT NULL CHECK(redeemed IN (0,1)),
                    allocation TEXT,UNIQUE(k,g))''')
                db.execute('''CREATE TABLE sk_certificate_events(
                    seq INTEGER PRIMARY KEY,event TEXT NOT NULL,certificate_id TEXT NOT NULL,payload TEXT NOT NULL)''')
            self.require({x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE name IN ('sk_certificates','sk_certificate_events')")}==
                         {'sk_certificates','sk_certificate_events'},'CERTIFICATE_STORE_MISSING')

    def _emit(self,event):
        self.certificate_trace(event)

    def _event(self,db,event,cid,value):
        db.execute('INSERT INTO sk_certificate_events(event,certificate_id,payload) VALUES(?,?,?)',
                   (event,cid,canonical(value).decode()))

    def assign(self,k,h,expected,uid,actor):
        self.require(type(expected) is int and expected==0,'CERTIFICATE_REQUIRED_FOR_HANDOFF')
        return super().assign(k,h,expected,uid,actor)

    def certify_nonexecution(self,k,h,generation,successor,actor):
        self.require(type(actor) is int and actor==self.controller and
                     type(generation) is int and generation>0 and
                     type(successor) is int and successor in self.requesters,'CONTROL_ROLE')
        self.require(k['sink']==self.profile and k['deployment']==self.certificate_deployment,'SINK_DEPLOYMENT')
        kt=key_text(k)
        # BEGIN IMMEDIATE on the actual consumer.db/resource.db: waits behind
        # an admitted old native writer; it cannot certify through its COMMIT.
        with self.open_control() as db:
            db.set_trace_callback(lambda sql:self._emit('CERT_BEGIN_ATTEMPT') if sql.strip().upper()=='BEGIN IMMEDIATE' else None)
            with transaction(db):
                self._emit('CERT_BEGIN_ACQUIRED')
                row=self.business(db,kt,h);old=self.latest(db,kt)
                self.require(old is not None and old[0]==generation,'STALE_ATTEMPT')
                policy,epoch,revoked=self.control(db)
                self.require(not revoked and policy==self.policy,'BRIDGE_REVOKED')
                if row[2] is not None:
                    self._emit('CERT_OBSERVED_COMMITTED_RESULT')
                    return dict(disposition='RESULT_RETRIEVED',result=json.loads(row[2]))
                self.no_unrecorded_effect(db,kt)
                self.require(old[4] in ('OPEN','FENCED'),'RESULT_INCONSISTENT')
                previous=db.execute('SELECT envelope FROM sk_certificates WHERE k=? AND g=?',(kt,generation)).fetchone()
                if previous:
                    cert=json.loads(previous[0])
                    self.require(cert['body']['successor_uid']==successor,'CERTIFICATE_SUCCESSOR_CONFLICT')
                    return dict(disposition='NONEXECUTION_CERTIFICATE_RETRIEVED',certificate=cert)
                content=json.loads(row[0])
                version=db.execute('SELECT version FROM '+self.table+' WHERE target=?',(content['target'],)).fetchone()
                self.require(version==(content['expected_version'],),'SQL_PRECONDITION')
                body=dict(schema='NATIVE-NONEXECUTION-CERTIFICATE/1',certificate_id=uuid.uuid4().hex,
                    key=k,content_hash=h,sink_public=public(self.sink_key),policy=policy,
                    fenced_generation=generation,fenced_attempt_id=old[1],fenced_subject_uid=old[2],
                    fenced_native_operation_id=old[3],successor_uid=successor,epoch_at_fence=epoch,
                    disposition='NONEXECUTION_FENCED')
                cert=signed(self.sink_key,DOMAIN,body)
                db.execute("UPDATE sk_attempts SET state='FENCED' WHERE k=? AND g=?",(kt,generation))
                db.execute('INSERT INTO sk_certificates VALUES(?,?,?,?,?,0,NULL)',
                           (body['certificate_id'],kt,generation,h,canonical(cert).decode()))
                self._event(db,'FENCE_AND_CERTIFICATE',body['certificate_id'],cert)
                self.certificate_fault('before_certificate_commit')
        self._emit('CERT_COMMIT_RETURNED')
        self.certificate_fault('after_certificate_commit')
        return dict(disposition='NONEXECUTION_CERTIFICATE_CREATED',certificate=cert)

    def redeem(self,certificate,actor):
        self.require(type(actor) is int and actor==self.controller,'CONTROL_ROLE')
        body=verify(certificate,public(self.sink_key),DOMAIN)
        self.auth.exact_shape(body,FIELDS)
        self.require(body['schema']=='NATIVE-NONEXECUTION-CERTIFICATE/1' and
                     body['disposition']=='NONEXECUTION_FENCED' and
                     body['sink_public']==public(self.sink_key) and
                     type(body['fenced_generation']) is int and body['fenced_generation']>0 and
                     type(body['fenced_subject_uid']) is int and body['fenced_subject_uid'] in self.requesters and
                     type(body['successor_uid']) is int and body['successor_uid'] in self.requesters and
                     type(body['epoch_at_fence']) is int and body['epoch_at_fence']>=0,'CERTIFICATE_BODY')
        k=body['key'];h=body['content_hash'];g=body['fenced_generation'];uid=body['successor_uid'];kt=key_text(k)
        self.require(k['sink']==self.profile and k['deployment']==self.certificate_deployment,'SINK_DEPLOYMENT')
        with self.open_control() as db,transaction(db):
            policy,_,revoked=self.control(db)
            self.require(not revoked and body['policy']==policy==self.policy,'BRIDGE_REVOKED')
            record=db.execute('SELECT envelope,redeemed FROM sk_certificates WHERE id=?',
                              (body['certificate_id'],)).fetchone()
            self.require(record is not None and record[0]==canonical(certificate).decode(),'CERTIFICATE_NOT_IN_AUTHORITY')
            self.require(record[1]==0,'CERTIFICATE_ALREADY_USED')
            row=self.business(db,kt,h);old=self.latest(db,kt)
            self.require(row[2] is None,'RESULT_ALREADY_COMMITTED')
            self.no_unrecorded_effect(db,kt)
            self.require(old==(g,body['fenced_attempt_id'],body['fenced_subject_uid'],
                               body['fenced_native_operation_id'],'FENCED'),'CERTIFICATE_FENCE_MISMATCH')
            generation=g+1;attempt=uuid.uuid4().hex
            rid=hashlib.sha256(b'SAME-K-NATIVE-ATTEMPT/1\x00'+canonical([k,h,generation,attempt,uid])).hexdigest()
            allocation=dict(key=k,h=h,generation=generation,attempt_id=attempt,uid=uid,rid=rid)
            db.execute("INSERT INTO sk_attempts VALUES(?,?,?,?,?,'OPEN')",(kt,generation,attempt,uid,rid))
            db.execute('INSERT OR IGNORE INTO sk_readers VALUES(?,?)',(kt,uid))
            db.execute('UPDATE sk_certificates SET redeemed=1,allocation=? WHERE id=?',
                       (canonical(allocation).decode(),body['certificate_id']))
            self._event(db,'CERTIFICATE_REDEEMED',body['certificate_id'],allocation)
            self.certificate_fault('before_handoff_commit')
        self.certificate_fault('after_handoff_commit')
        return allocation

    def read_handoff(self,certificate_id,actor):
        self.require(type(actor) is int and actor==self.controller,'CONTROL_ROLE')
        with self.open_control() as db:
            row=db.execute('SELECT redeemed,allocation FROM sk_certificates WHERE id=?',(certificate_id,)).fetchone()
            self.require(row is not None and row[0]==1 and row[1] is not None,'HANDOFF_NOT_COMMITTED')
            return dict(disposition='EXISTING_ALLOCATION_ONLY',allocation=json.loads(row[1]),
                        new_allocation_created=False)
