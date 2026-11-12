"""Real versioned facade contracts, with native/DB/grant entry forbidden sentinels."""
import ast,copy,json,sqlite3,sys,unittest
from pathlib import Path
from types import SimpleNamespace
HERE=Path(__file__).resolve().parent;FROZEN=HERE.parent/'native_admission_01/sources'
sys.path[:0]=[str(HERE),str(FROZEN/'support/fci-same-k-handoff-20261030'),str(FROZEN/'crash'),str(FROZEN/'task')]
import execution as ex
import capability as cap
import handoff as h
import quiescence as q
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
def need(x,s):
    if not x:raise h.Refused(s)
class Capabilities(unittest.TestCase):
    def setUp(self):
        self.key=Key.generate();self.b=object.__new__(ex.Execution);self.b.require=need;self.calls=[]
        def forbidden(name):
            def f(*a,**kw):self.calls.append(name);raise AssertionError('UNEXPECTED_ENTRY:'+name)
            return f
        self.b.open_control=forbidden('DB');self.b.grant=forbidden('GRANT');self.b.history_C=forbidden('HISTORY')
        node=next(x for x in ast.parse((HERE/'owner.py').read_text()).body if isinstance(x,ast.ClassDef) and x.name=='Endpoint')
        env=dict(q=q,b=self.b,Refused=h.Refused,InvalidSignature=InvalidSignature,sqlite3=sqlite3,Service=SimpleNamespace(handle=lambda *_:None),signed=h.signed,sink=self.key,RPC=ex.RPC,policy=ex.policy)
        exec(compile(ast.Module(body=[node],type_ignores=[]),'versioned.Endpoint','exec'),env);self.endpoint=env['Endpoint']()
    def call(self,op,args,uid):return self.endpoint.dispatch(dict(op=op,args=args),uid)
    def reject(self,fn,code):
        with self.assertRaises(h.Refused) as caught:fn()
        self.assertEqual(str(caught.exception),code);self.assertEqual(self.calls,[])
    def test_signed_capabilities_for_C(self):
        v=self.call('capabilities_C',{},62026);self.assertEqual(v['result'],cap.descriptor())
        self.assertEqual(q.verify(v['receipt'],h.public(self.key),ex.RPC),dict(schema='FCI-C-NATIVE-EXECUTION-RPC/2',op='capabilities_C',uid=62026,result_digest=q.digest(v['result']),execution_policy=ex.policy()))
    def test_capabilities_for_control(self):self.assertEqual(self.call('capabilities_C',{},62022)['result']['supported_new_effect'],[cap.SAMPLED])
    def test_capabilities_wrong_role(self):self.reject(lambda:self.call('capabilities_C',{},62023),'C_CAPABILITY_ROLE')
    def test_deadline_issue_before_grant_or_write(self):self.reject(lambda:self.b.issue_C('d'*32,25,cap.DEADLINE),'C_COMMIT_DEADLINE_UNQUALIFIED')
    def test_deadline_execute_before_DB_or_history(self):self.reject(lambda:self.b.execute_C({'cached':'permit'},{'cached':'result'},62026,cap.DEADLINE),'C_COMMIT_DEADLINE_UNQUALIFIED')
    def test_deadline_execute_wrong_role(self):self.reject(lambda:self.b.execute_C({}, {},62024,cap.DEADLINE),'C_ROLE')
    def test_missing_issue_argument(self):self.reject(lambda:self.call('issue_C',dict(challenge='d'*32,ttl=25),62022),'C_CAPABILITY_REQUIRED')
    def test_missing_execute_argument(self):self.reject(lambda:self.call('execute_C',dict(permit={},request={}),62026),'C_CAPABILITY_REQUIRED')
    def test_unknown_issue(self):self.reject(lambda:self.call('issue_C',dict(challenge='d'*32,ttl=25,required_capability='unknown'),62022),'C_CAPABILITY_UNKNOWN')
    def test_unknown_execute(self):self.reject(lambda:self.call('execute_C',dict(permit={},request={},required_capability='unknown'),62026),'C_CAPABILITY_UNKNOWN')
    def test_no_type_coercion(self):
        for value in (True,0,[],{},'sampled_admission'):
            with self.subTest(value=value):self.reject(lambda:cap.require_capability(value),'C_CAPABILITY_UNKNOWN')
    def test_explicit_null_is_missing(self):self.reject(lambda:cap.require_capability(None),'C_CAPABILITY_REQUIRED')
    def test_metadata_cannot_enable_deadline(self):
        d=cap.descriptor();d['commit_deadline_qualified']=True;d['supported_new_effect'].append(cap.DEADLINE)
        self.assertFalse(cap.descriptor()['commit_deadline_qualified']);self.reject(lambda:cap.require_capability(cap.DEADLINE),'C_COMMIT_DEADLINE_UNQUALIFIED')
    def test_strong_endpoint_has_no_cached_result_fallback(self):self.reject(lambda:self.call('execute_C',dict(permit={'cached':True},request={'already_committed':True},required_capability=cap.DEADLINE),62026),'C_COMMIT_DEADLINE_UNQUALIFIED')
    def test_sampled_is_an_explicit_supported_contract(self):self.assertEqual(cap.require_capability(cap.SAMPLED),cap.SAMPLED)
if __name__=='__main__':unittest.main(verbosity=2)
