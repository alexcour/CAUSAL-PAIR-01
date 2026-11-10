"""C admission owner with real kernel UID control; no RPC-supplied grant or pin."""
import argparse,json,os,socket,sys,traceback
from pathlib import Path
p=argparse.ArgumentParser()
for n in ('stage','runtime','work','socket','gate-context','grant'):p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--profile',required=True);a=p.parse_args()
sys.path[:0]=[str(Path(__file__).resolve().parent),str(a.stage/'retirement'),str(a.stage/'crash'),str(a.stage/'task'),str(a.stage/'support/fci-same-k-handoff-20261030'),str(a.stage/'reference'),str(a.stage/'recovery')]
from uds_service import Service,harden
from handoff import Refused,public
from snapshots import root_snapshot
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
import quiescence as q
from retirement import Retirement
from admission import Admission,RPC
q.need(os.getuid()==os.geteuid()==62021,'OWNER_UID');identity=harden()
prepared=json.loads((a.work/'prepared.json').read_text());context,proof=q.load_context(a.gate_context)
sink=Key.from_private_bytes(bytes.fromhex(json.loads((a.runtime/'bridge-private.json').read_text())['sink']))
component=Admission(Retirement(a.stage,a.runtime,a.profile,prepared,context,proof,sink,root_snapshot),a.grant)
class Endpoint:
    roles={uid:uid for uid in (62022,62023,62024,62026)}
    handle=Service.handle
    def dispatch(self,r,uid):
        if uid!=62022:raise Refused('CONTROL_ROLE')
        q.need(type(r) is dict and set(r)=={'op','args'} and r['args']=={},'REQUEST_SHAPE')
        op=r['op']
        try:
            if op=='admit_C':result=component.admit()
            elif op=='probe_issue_C':result=component.probe_issue()
            elif op=='abort_admission_trial':
                before=component.r.stores()
                try:component.admit(abort=True);raise ValueError('ABORT_NOT_TRIGGERED')
                except RuntimeError as exc:
                    q.need(str(exc)=='INJECTED_ADMISSION_BEFORE_COMMIT' and component.r.stores()==before,'REAL_ADMISSION_ROLLBACK')
                    result=dict(status='ABORT_ROLLED_BACK',stores_unchanged=True)
            else:raise Refused('OP')
        except Refused:raise
        except Exception:traceback.print_exc();raise
        return dict(result=result,receipt=q.signed(sink,RPC,dict(schema='FCI-NATIVE-C-ADMISSION-RPC/1',op=op,uid=uid,
            result_digest=q.digest(result),execution_authorized=False,recovery_authorized=False)))
with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener:
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);listener.bind(str(a.socket));a.socket.chmod(0o666);listener.listen(8)
    print(json.dumps(dict(pid=os.getpid(),identity=identity,sink_public=public(sink),normal_service_constructor_called=False,rearm_called=False)),flush=True)
    endpoint=Endpoint()
    while True:
        conn,_=listener.accept();endpoint.handle(conn)
