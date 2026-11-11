"""Kernel UID RPC owner for activation and dry authorization; no execute route."""
import argparse,json,os,socket,sys,sqlite3,traceback
from pathlib import Path
p=argparse.ArgumentParser()
for n in ('stage','runtime','work','socket','gate-context','admission-grant','grant'):p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--profile',required=True);args=p.parse_args()
sys.path[:0]=[str(Path(__file__).resolve().parent),str(args.stage/'admission'),str(args.stage/'retirement'),str(args.stage/'crash'),str(args.stage/'task'),str(args.stage/'support/fci-same-k-handoff-20261030'),str(args.stage/'reference'),str(args.stage/'recovery')]
from uds_service import Service,harden
from handoff import Refused,public
from snapshots import root_snapshot
from retirement import Retirement
import quiescence as q
from activation import Activation,RPC,policy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
q.need(os.getuid()==os.geteuid()==62021,'OWNER_UID');identity=harden()
prepared=json.loads((args.work/'prepared.json').read_text());context,proof=q.load_context(args.gate_context)
sink=Key.from_private_bytes(bytes.fromhex(json.loads((args.runtime/'bridge-private.json').read_text())['sink']))
component=Activation(Retirement(args.stage,args.runtime,args.profile,prepared,context,proof,sink,root_snapshot),args.admission_grant,args.grant)
class Endpoint:
    roles={uid:uid for uid in (62022,62023,62024,62026)};handle=Service.handle
    def dispatch(self,r,uid):
        q.need(type(r) is dict and set(r)=={'op','args'} and type(r['args']) is dict,'RPC_SHAPE')
        op=r['op'];a=r['args']
        if op=='authorize_C':
            if uid!=62026:raise Refused('C_ROLE')
        elif uid!=62022:raise Refused('CONTROL_ROLE')
        try:
            if op=='activate_C':q.need(a=={},'ACTIVATE_ARGS');result=component.activate()
            elif op=='abort_activation':
                q.need(a=={},'ABORT_ARGS');before=component.r.stores()
                try:component.activate(abort=True);raise ValueError('ABORT_NOT_TRIGGERED')
                except RuntimeError as e:
                    q.need(str(e)=='INJECTED_ACTIVATION_ABORT' and before==component.r.stores(),'ACTIVATION_ROLLBACK')
                    result=dict(status='ABORT_ROLLED_BACK',stores_unchanged=True)
            elif op=='issue_C':q.need(set(a)=={'challenge','ttl'},'ISSUE_ARGS');result=component.issue(a['challenge'],a['ttl'])
            elif op=='authorize_C':q.need(set(a)=={'permit','request'},'AUTHORIZE_ARGS');result=component.authorize(a['permit'],a['request'],uid)
            elif op=='revoke_C':q.need(a=={},'REVOKE_ARGS');result=component.revoke()
            else:raise Refused('OP')
        except Refused:raise
        except InvalidSignature:raise Refused('SIGNATURE_INVALID')
        except (ValueError,OSError,sqlite3.Error) as e:raise Refused(str(e) if isinstance(e,ValueError) else 'AUTHORITY_UNAVAILABLE')
        except Exception:traceback.print_exc();raise
        return dict(result=result,receipt=q.signed(sink,RPC,dict(schema='FCI-C-ACTIVATION-RPC/1',op=op,uid=uid,
            result_digest=q.digest(result),activation_policy=policy(),native_execution_called=False,rearm_called=False)))
with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener:
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);listener.bind(str(args.socket));args.socket.chmod(0o666);listener.listen(8)
    print(json.dumps(dict(pid=os.getpid(),identity=identity,sink_public=public(sink),native_execution_called=False,normal_native_constructor_called=False,rearm_called=False)),flush=True)
    endpoint=Endpoint()
    while True:
        conn,_=listener.accept();endpoint.handle(conn)
