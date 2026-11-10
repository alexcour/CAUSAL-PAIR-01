"""New read-only owner. No native engine construction, rearm or execution."""
import argparse,hashlib,json,os,socket,sys
from pathlib import Path
p=argparse.ArgumentParser()
for n in ('stage','runtime','work','socket'):p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--profile',required=True);p.add_argument('--gate-context',type=Path,required=True);a=p.parse_args()
sys.path.insert(0,str(Path(__file__).resolve().parent))
import quiescence as q
sys.path[:0]=[str(a.stage/'task'),str(a.stage/'support/fci-same-k-handoff-20261030'),str(a.stage/'reference'),str(a.stage/'recovery')]
from uds_service import Service,harden
from handoff import Refused,canonical,public,signed,key_text
from snapshots import root_snapshot
from recovery import recovery_gate,RecoveryHeld
from attribution import check
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
def need(ok,reason):
    if not ok:raise Refused(reason)
def digest(x):return hashlib.sha256(canonical(x)).hexdigest()
need(os.getuid()==os.geteuid()==62021,'OWNER');identity=harden()
keys=json.loads((a.runtime/'bridge-private.json').read_text());sink=Key.from_private_bytes(bytes.fromhex(keys['sink']))
prepared=json.loads((a.work/'prepared.json').read_text());context=prepared['context']
NAMES=('consumer.db','spend.db','anchor.db','replica.db') if a.profile=='FCI' else ('resource.db','reference.db')
class GateView:controller=62022
def inspect(query_id,uid):
    need(uid==62023 and type(query_id) is str and len(query_id)==32,'READ_ROLE')
    missing=[n for n in NAMES if not (a.runtime/n).is_file()]
    state=legacy=producer=None;gate_called=False
    if missing:gate=dict(status='HOLD',code='AUTHORITY_FILE_UNAVAILABLE',missing=missing)
    else:
        snap=root_snapshot(a.runtime,a.profile);state=snap['stores']
        main=state[NAMES[0]];business=main['sk_business']['rows'];producers=main['producer_results']['rows']
        need(len(business)==1 and [business[0][0],uid] in main['sk_readers']['rows'],'DURABLE_READER_GRANT')
        legacy=json.loads(business[0][3]) if business[0][3] is not None else None
        producer=json.loads(producers[0][2]) if len(producers)==1 else None
        if legacy is not None and producer is not None:
            check(producer,prepared['producer_authorization'],prepared['request_B'],legacy,a.profile,
                producer['body']['participant_invocation'],context['issuer_public'],public(sink))
        supervisor_path=a.work/'supervisor-B.json'
        if not supervisor_path.is_file():gate=dict(status='HOLD',code='SUPERVISOR_PROOF_UNAVAILABLE')
        else:
            supervisor=json.loads(supervisor_path.read_text());gate_called=True
            try:gate=recovery_gate(GateView(),context,62022,supervisor)
            except RecoveryHeld as exc:gate=dict(status='HOLD',code=str(exc))
    # Never reinterpret absence as nonexecution; this endpoint grants no retry.
    outcome='HISTORICAL_PRODUCER_RESULT' if legacy is not None and producer is not None else 'HOLD_OUTCOME_UNAVAILABLE'
    body=dict(schema='GUARDED-CRASH-READ/1',profile=a.profile,query_id=query_id,uid=uid,outcome=outcome,
        state_digest=digest(state),legacy_digest=digest(legacy),producer_digest=digest(producer),gate=gate,
        gate_called=gate_called,new_execution=False,execution_authorized=False,recovery_authorized=False)
    result=dict(state=state,legacy=legacy,producer=producer,query=signed(sink,b'GUARDED-CRASH-READ/1\0',body),
        outcome=outcome,gate=gate,gate_called=gate_called,new_execution=False,execution_authorized=False,recovery_authorized=False)
    gate_context,proof=q.load_context(a.gate_context)
    decision=q.decide(gate_context,proof,prepared,state,q.inventory(a.runtime,a.profile))
    result['gate_v2']=signed(sink,q.DECISION,dict(schema='FCI-QUIESCENCE-DECISION/2',query_id=query_id,uid=uid,
        context_digest=q.digest(gate_context),proof_digest=q.digest(proof),state_digest=q.digest(state),decision=decision))
    return result
class Endpoint:
    roles={62022:62022,62023:62023,62024:62024}
    handle=Service.handle
    def dispatch(self,r,uid):
        need(type(r) is dict and set(r)=={'op','args'} and r['op']=='inspect' and set(r['args'])=={'query_id'},'READ_REQUEST')
        return inspect(r['args']['query_id'],uid)
need(not {'sql_service','standard'}&set(sys.modules),'NO_NATIVE_ENGINE_IMPORT')
with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener:
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);listener.bind(str(a.socket));a.socket.chmod(0o666);listener.listen(8)
    print(json.dumps(dict(pid=os.getpid(),identity=identity,sink_public=public(sink),native_engine_constructed=False,rearm_called=False)),flush=True)
    endpoint=Endpoint()
    while True:
        conn,_=listener.accept();endpoint.handle(conn)
