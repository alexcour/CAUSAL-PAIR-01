"""Kernel-authenticated closure owner; explicit frozen decoder/API views, no startup."""
import argparse,json,os,socket,sys
from pathlib import Path
p=argparse.ArgumentParser()
for n in ('stage','runtime','work','socket','gate-context'):p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--profile',required=True);a=p.parse_args()
sys.path[:0]=[str(Path(__file__).resolve().parent),str(a.stage/'crash'),str(a.stage/'task'),str(a.stage/'support/fci-same-k-handoff-20261030'),str(a.stage/'reference'),str(a.stage/'recovery')]
from uds_service import Service,harden
from handoff import Refused,public
from snapshots import root_snapshot
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
import quiescence as q
from retirement import Retirement
q.need(os.getuid()==os.geteuid()==62021,'OWNER_UID');identity=harden()
prepared=json.loads((a.work/'prepared.json').read_text());context,proof=q.load_context(a.gate_context)
private=json.loads((a.runtime/'bridge-private.json').read_text());sink=Key.from_private_bytes(bytes.fromhex(private['sink']))
component=Retirement(a.stage,a.runtime,a.profile,prepared,context,proof,sink,root_snapshot)
REPLY=b'FCI-NATIVE-RETIREMENT-RPC/1\0'
class Endpoint:
    roles={62022:62022,62023:62023,62024:62024}
    handle=Service.handle
    def dispatch(self,r,uid):
        try:return self.checked_dispatch(r,uid)
        except Refused:raise
        except Exception:
            import traceback
            traceback.print_exc()
            raise
    def checked_dispatch(self,r,uid):
        q.need(type(r) is dict and set(r)=={'op','args'} and r['args']=={},'REQUEST_SHAPE')
        op=r['op']
        if op=='probe_B':
            if uid!=62024:raise Refused('B_ROLE')
            result=component.probes(uid)
        else:
            if uid!=62022:raise Refused('CONTROL_ROLE')
            if op=='abort_retirement_trial':
                before=component.stores()
                try:result=component.close(abort=True)
                except RuntimeError as exc:
                    q.need(str(exc)=='INJECTED_RETIREMENT_BEFORE_COMMIT','EXACT_INJECTED_ABORT')
                    q.need(component.stores()==before,'RETIREMENT_ABORT_ROLLED_BACK')
                    result=dict(status='ABORT_ROLLED_BACK',injected_fault=True,stores_unchanged=True)
            elif op=='close_B':result=component.close()
            else:raise Refused('OP')
        envelope=q.signed(sink,REPLY,dict(schema='FCI-NATIVE-RETIREMENT-RPC/1',op=op,uid=uid,result_digest=q.digest(result),
            execution_authorized=False,recovery_authorized=False,handoff_authorized=False))
        return dict(result=result,receipt=envelope)
with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener:
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);listener.bind(str(a.socket));a.socket.chmod(0o666);listener.listen(8)
    print(json.dumps(dict(pid=os.getpid(),identity=identity,sink_public=public(sink),normal_service_constructor_called=False,rearm_called=False)),flush=True)
    endpoint=Endpoint()
    while True:
        conn,_=listener.accept();endpoint.handle(conn)
