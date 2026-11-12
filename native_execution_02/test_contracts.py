"""Local contract regressions; no native owner, UID changes or qualification claim.

Actual check_C and Endpoint.dispatch are exercised with a small SQLite fixture.
Endpoint is extracted with AST to avoid executing its root/UDS launcher.
"""
import ast,copy,importlib.util,json,os,sqlite3,sys,unittest
import tempfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key

HERE=Path(__file__).resolve().parent
FROZEN=HERE.parent/'native_admission_01/sources'
sys.path[:0]=[str(HERE),str(FROZEN/'support/fci-same-k-handoff-20261030'),str(FROZEN/'crash'),str(FROZEN/'task')]
import handoff as h
import quiescence as q
import execution as ex
import native_finalization as nf
import capability as cap
spec=importlib.util.spec_from_file_location('contract_reader',HERE/'receive.py')
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)

def need(ok,code):
    if not ok:raise h.Refused(code)

class Contracts(unittest.TestCase):
    def setUp(self):
        self.key=Key.generate();self.pin=h.public(self.key)
        self.b=object.__new__(ex.Execution);b=self.b
        b.sink_key=self.key;b.activation={'fixture':'activation'};b.allocation=dict(uid=62026,rid='r')
        b.check_failures=[];b.execute_entry_calls=0;b.epoch=lambda:7;b.require=need
        self.grant={'fixture':'grant'};self.control=dict(native_epoch=7,boot_id='fixture-boot')
        b.grant=lambda purpose:(self.grant,self.control)
        self.db=sqlite3.connect(':memory:')
        self.db.executescript('CREATE TABLE c_execution_permits(challenge,envelope,request);CREATE TABLE c_activations(rid,status);')
        self.db.execute('INSERT INTO c_activations VALUES(?,?)',('r','ACTIVE'))
        self.request={'fixture':'request'}
        body=dict(schema='FCI-C-NATIVE-CONSUMABLE-PERMIT/2',grant_digest=q.digest(self.grant),activation_digest=q.digest(b.activation),
            allocation=b.allocation,request_digest=q.digest(self.request),execution_policy=ex.policy(),owner_pid=os.getpid(),
            native_epoch=7,boot_id='fixture-boot',not_before=100,not_after=125,challenge='c'*32,temporal_capability=cap.SAMPLED)
        self.permit=h.signed(self.key,ex.PERMIT,copy.deepcopy(body))
        self.db.execute('INSERT INTO c_execution_permits VALUES(?,?,?)',('c'*32,h.canonical(self.permit).decode(),h.canonical(self.request).decode()))
        b.check=lambda db,request,uid:None
        def execute_C(permit,request,uid,required_capability):
            cap.require_capability(required_capability)
            b.check_C(self.db,permit,request,uid)
            b.execute_entry_calls+=1
            return {'fixture':'validated-only'}
        b.execute_C=execute_C
        nodes=ast.parse((HERE/'owner.py').read_text()).body
        node=next(x for x in nodes if isinstance(x,ast.ClassDef) and x.name=='Endpoint')
        env=dict(q=q,b=b,Refused=h.Refused,InvalidSignature=InvalidSignature,sqlite3=sqlite3,
            Service=SimpleNamespace(handle=lambda *_:None),signed=h.signed,sink=self.key,RPC=ex.RPC,policy=ex.policy)
        exec(compile(ast.Module(body=[node],type_ignores=[]),'owner.Endpoint','exec'),env)
        self.endpoint=env['Endpoint']()
        self.clock=patch.object(ex.time,'monotonic',return_value=110);self.clock.start()
    def tearDown(self):self.clock.stop();self.db.close()
    def dispatch(self,permit=None,request=None):
        return self.endpoint.dispatch(dict(op='execute_C',args=dict(permit=self.permit if permit is None else permit,request=self.request if request is None else request,required_capability=cap.SAMPLED)),62026)
    def rejects(self,permit,code,request=None):
        before=self.db.total_changes
        with self.assertRaises(h.Refused) as err:self.dispatch(permit,request)
        self.assertEqual(str(err.exception),code);self.assertEqual(self.b.execute_entry_calls,0);self.assertEqual(self.db.total_changes,before)
        return err.exception
    def test_positive_wrapper(self):
        result=self.dispatch();self.assertEqual(result['result'],{'fixture':'validated-only'});self.assertEqual(self.b.execute_entry_calls,1)
    def test_signature_bit_only(self):
        p=copy.deepcopy(self.permit);s=bytearray.fromhex(p['signature']);s[0]^=1;p['signature']=s.hex()
        e=self.rejects(p,'SIGNATURE_INVALID');self.assertIsInstance(e.__cause__,h.Refused);self.assertIsInstance(e.__cause__.__cause__,InvalidSignature)
    def test_body_tamper_before_binding(self):
        p=copy.deepcopy(self.permit);p['body']['allocation']['uid']=62024;self.rejects(p,'SIGNATURE_INVALID')
    def test_resigned_wrong_binding(self):
        body=copy.deepcopy(self.permit['body']);body['allocation']['uid']=62024;p=h.signed(self.key,ex.PERMIT,body)
        self.assertEqual(q.verify(p,self.pin,ex.PERMIT),body);self.rejects(p,'C_PERMIT_BINDING')
    def test_resigned_unqualified_capability(self):
        body=copy.deepcopy(self.permit['body']);body['temporal_capability']=cap.DEADLINE
        p=h.signed(self.key,ex.PERMIT,body)
        self.assertEqual(q.verify(p,self.pin,ex.PERMIT),body);self.rejects(p,'C_PERMIT_BINDING')
    def test_request_binding(self):self.rejects(self.permit,'C_PERMIT_BINDING',{'fixture':'different'})
    def test_foreign_key(self):self.rejects(h.signed(Key.generate(),ex.PERMIT,self.permit['body']),'SIGNATURE_INVALID')
    def test_wrong_domain(self):self.rejects(h.signed(self.key,b'WRONG-DOMAIN/1\0',self.permit['body']),'SIGNATURE_INVALID')
    def test_shape_not_relabelled(self):self.rejects({'body':self.permit['body']},'SHAPE')
    def test_other_refusal_preserved(self):
        self.b.grant=lambda purpose:need(False,'TRANSITION_GRANT_EXPIRED')
        self.rejects(self.permit,'TRANSITION_GRANT_EXPIRED')
    def test_unknown_native_verdict_not_relabelled(self):
        self.b.execute_C=lambda **kwargs:dict(response=dict(status='HOLD_NATIVE',native=dict(code='OUTCOME_UNKNOWN')))
        self.assertEqual(self.dispatch()['result']['response']['status'],'HOLD_NATIVE')
    def test_reader_exact_refusals(self):
        c=dict(client_uid=62026,client_pid=1,response=dict(ok=False,error='SIGNATURE_INVALID',peer=dict(pid=1,uid=62026,gid=62026)))
        reader.denied(c,62026,'SIGNATURE_INVALID')
        for field,value in [('error','SIGNATURE'),('error','C_PERMIT_BINDING'),('ok',True)]:
            bad=copy.deepcopy(c);bad['response'][field]=value
            with self.assertRaises(ValueError):reader.denied(bad,62026,'SIGNATURE_INVALID')
        bad=copy.deepcopy(c);bad['response']['peer']['uid']=62024
        with self.assertRaises(ValueError):reader.denied(bad,62026,'SIGNATURE_INVALID')
    def test_clock_failure_recorded_and_propagated(self):
        with patch.object(ex.time,'monotonic',return_value=125):self.rejects(self.permit,'C_PERMIT_EXPIRED')
        self.assertEqual(self.b.check_failures[-1]['code'],'C_PERMIT_EXPIRED')
        self.assertEqual(self.b.check_failures[-1]['stage'],'precheck')

class ReadGrantContracts(unittest.TestCase):
    def test_history_result_uses_wire_JSON_types(self):
        key=Key.generate();a=dict(uid=62026,rid='C',key=dict(scope='C',deployment='fixture',sink='STANDARD',operation_id='business-C'),h='h')
        request={'native':'request'};value={'fixture':'result'}
        permit=h.signed(key,ex.PERMIT,dict(allocation=a,request_digest=q.digest(request),not_before=100,not_after=125,temporal_capability=cap.SAMPLED,execution_policy=ex.policy()))
        with sqlite3.connect(':memory:') as db:
            db.executescript('CREATE TABLE c_permit_consumptions(challenge,permit_digest,rid,result_digest,checked_tick);CREATE TABLE c_execution_permits(challenge,envelope,request);')
            db.execute('INSERT INTO c_execution_permits VALUES(?,?,?)',('c',h.canonical(permit).decode(),h.canonical(request).decode()))
            db.execute('INSERT INTO c_permit_consumptions VALUES(?,?,?,?,?)',('c',q.digest(permit),'C',q.digest(value),110))
            b=object.__new__(ex.Execution);b.allocation=a;b.sink_key=key;b.profile='STANDARD';b.require=need
            b.open_control=lambda:nullcontext(db);b.business=lambda *args:(None,None,h.canonical(value).decode());b.read_result=lambda *args:value
            b.engine=SimpleNamespace(inspect=lambda rid:dict(effect_status='COMMITTED_PROVEN'))
            result=b.history_C(62026)
            self.assertIsInstance(result['consumption'],list)
            self.assertEqual(json.loads(h.canonical(result)),result)
    def fixture(self):
        db=sqlite3.connect(':memory:',isolation_level=None)
        db.executescript('CREATE TABLE c_execution_permits(challenge TEXT PRIMARY KEY,envelope,request);CREATE TABLE sk_readers(k,uid,PRIMARY KEY(k,uid));')
        db.execute('INSERT INTO sk_readers VALUES(?,?)',('predecessor',62024))
        return db
    def test_permit_and_C_read_grant_rollback_together(self):
        with self.fixture() as db:
            db.execute('BEGIN IMMEDIATE')
            ex.persist_permit_and_read_grant(db,'c',{'body':'permit'},{'native':'request'},{'uid':62026,'key':{'scope':'C','deployment':'fixture','sink':'FCI','operation_id':'business-C'}})
            self.assertEqual(db.execute('SELECT uid FROM sk_readers WHERE k=?',(h.key_text({'scope':'C','deployment':'fixture','sink':'FCI','operation_id':'business-C'}),)).fetchall(),[(62026,)])
            self.assertEqual(db.execute('SELECT count(*) FROM c_execution_permits').fetchone(),(1,))
            db.rollback()
            self.assertEqual(db.execute('SELECT * FROM sk_readers').fetchall(),[('predecessor',62024)])
            self.assertEqual(db.execute('SELECT count(*) FROM c_execution_permits').fetchone(),(0,))
    def test_read_grant_is_scoped_and_preserves_predecessor(self):
        with self.fixture() as db:
            db.execute('BEGIN IMMEDIATE')
            ex.persist_permit_and_read_grant(db,'c',{'body':'permit'},{'native':'request'},{'uid':62026,'key':{'scope':'C','deployment':'fixture','sink':'FCI','operation_id':'business-C'}})
            db.commit()
            self.assertEqual(set(db.execute('SELECT * FROM sk_readers')),{('predecessor',62024),(h.key_text({'scope':'C','deployment':'fixture','sink':'FCI','operation_id':'business-C'}),62026)})
            self.assertEqual(db.execute('SELECT count(*) FROM c_execution_permits').fetchone(),(1,))
    def test_grant_requires_real_transaction_and_C(self):
        with self.fixture() as db:
            for allocation in ({'uid':62026,'key':{}},{'uid':62024,'key':{}}):
                with self.assertRaises(ValueError):ex.persist_permit_and_read_grant(db,'c',{}, {}, allocation)
            self.assertEqual(db.total_changes,1)

class FinalizationContracts(unittest.TestCase):
    def test_only_exact_policy_errors_escape_native_unknown_handlers(self):
        for code in ('C_PERMIT_EXPIRED','C_REVOKED'):
            with self.assertRaises(nf.PolicyStop) as caught:nf.policy_call(lambda:need(False,code),'admit')
            self.assertEqual((caught.exception.code,caught.exception.stage),(code,'admit'))
            self.assertNotIsInstance(caught.exception,Exception)
            self.assertIsInstance(caught.exception.__cause__,h.Refused)
        for code in ('TRANSITION_GRANT_EXPIRED','NATIVE_FAILURE','OUTCOME_UNKNOWN'):
            with self.assertRaises(h.Refused) as caught:nf.policy_call(lambda:need(False,code),'admit')
            self.assertEqual(str(caught.exception),code)
    def test_rollback_reads_real_durable_preimage(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'main.db';db=sqlite3.connect(path,isolation_level=None)
            try:
                db.execute('CREATE TABLE state(id PRIMARY KEY,value)');db.execute('INSERT INTO state VALUES(1,10)')
                before=nf.logical_main(db);db.execute('BEGIN IMMEDIATE');db.execute('UPDATE state SET value=20')
                engine=SimpleNamespace(native_tx_before=before,native_commit_seen=False,consumer=SimpleNamespace(db=db))
                a,b=nf.verified_rollback(engine,path)
                self.assertEqual(a,b);self.assertEqual(db.execute('SELECT value FROM state').fetchone(),(10,));self.assertFalse(db.in_transaction)
            finally:db.close()
    def test_committed_state_cannot_be_attested_as_precommit_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'main.db';db=sqlite3.connect(path,isolation_level=None)
            try:
                db.execute('CREATE TABLE state(value)');before=nf.logical_main(db);db.execute('INSERT INTO state VALUES(20)')
                engine=SimpleNamespace(native_tx_before=before,native_commit_seen=True,consumer=SimpleNamespace(db=db))
                with self.assertRaises(ValueError):nf.verified_rollback(engine,path)
                self.assertEqual(db.execute('SELECT value FROM state').fetchall(),[(20,)])
            finally:db.close()
    def test_application_stages_only_after_native_finalizers(self):
        db=sqlite3.connect(':memory:',isolation_level=None);db.execute('CREATE TABLE writes(kind)');db.execute('BEGIN IMMEDIATE')
        bridge=SimpleNamespace(active=({},62026),require=need,native_finalizations=[],fault=lambda point:None)
        bridge.admit=lambda *args:(0,0)
        bridge.finish=lambda *args:db.execute("INSERT INTO writes VALUES('consumption')")
        class Frozen:
            def __init__(self,*args,**kwargs):
                self.consumer=SimpleNamespace(db=db,_entry=lambda rid:dict(status='DONE'),_fence=lambda rid:dict(decision='COMMIT_FENCE_PASS',checked_at=100))
                self.active=dict(operation=dict(operation_id='C'))
            def capture(self,kind,data,raw,service):
                if kind=='tx_stage':db.execute("INSERT INTO writes VALUES('application')")
            def record(self,*args,**kwargs):pass
        class Candidate(nf.FinalizedSqlMixin,Frozen):pass
        try:
            service=Candidate(bridge=bridge)
            service.capture('tx_begin',dict(operation='finish'),{},service)
            service.capture('tx_stage',dict(operation='finish'),dict(result_new_effect=True),service)
            self.assertEqual(db.execute('SELECT * FROM writes').fetchall(),[])
            service.after_finalizers('after_commit_fence')
            self.assertEqual(db.execute('SELECT * FROM writes').fetchall(),[('application',),('consumption',)])
            self.assertTrue(db.in_transaction);db.rollback();self.assertEqual(db.execute('SELECT * FROM writes').fetchall(),[])
        finally:db.close()
    def test_native_finalizer_denial_never_stages_application(self):
        db=sqlite3.connect(':memory:',isolation_level=None);db.execute('CREATE TABLE writes(kind)');db.execute('BEGIN IMMEDIATE')
        bridge=SimpleNamespace(active=({},62026),require=need,native_finalizations=[],fault=lambda point:None,admit=lambda *args:(0,0),finish=lambda *args:None)
        class Frozen:
            def __init__(self,*args,**kwargs):
                self.consumer=SimpleNamespace(db=db,_entry=lambda rid:dict(status='PENDING'),_fence=lambda rid:dict(decision='BLOCK_COMMIT_DEADLINE'))
                self.active=dict(operation=dict(operation_id='C'))
            def capture(self,kind,data,raw,service):
                if kind=='tx_stage':db.execute("INSERT INTO writes VALUES('FORBIDDEN')")
            def record(self,*args,**kwargs):pass
        class Candidate(nf.FinalizedSqlMixin,Frozen):pass
        try:
            service=Candidate(bridge=bridge);service.capture('tx_stage',dict(operation='finish'),dict(result_new_effect=True),service)
            service.after_finalizers('after_commit_fence');self.assertEqual(db.execute('SELECT * FROM writes').fetchall(),[])
        finally:db.close()

if __name__=='__main__':unittest.main(verbosity=2)
