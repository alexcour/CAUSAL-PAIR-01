"""Kernel-credential UDS facade for the explicit C native composition."""
import argparse,json,os,socket,sys,traceback,sqlite3
from pathlib import Path
p=argparse.ArgumentParser()
for n in ('stage','runtime','work','socket','start-grant','live-grant','marker'):p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--profile',required=True);p.add_argument('--case',required=True);p.add_argument('--root-pin',required=True);args=p.parse_args()
sys.path[:0]=[str(args.stage/'execution'),str(args.stage/'crash'),str(args.stage/'task'),str(args.stage/'support/fci-same-k-handoff-20261030'),str(args.stage/'reference'),str(args.stage/'recovery')]
import quiescence as q
from execution import Execution,RPC,policy
from uds_service import Service,harden
from handoff import Refused,public,signed
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
q.need(os.getuid()==os.geteuid()==62021,'OWNER_UID');identity=harden()
keys=json.loads((args.runtime/'bridge-private.json').read_text());issuer=Key.from_private_bytes(bytes.fromhex(keys['issuer']));sink=Key.from_private_bytes(bytes.fromhex(keys['sink']))
b=Execution(args.stage,args.runtime,args.profile,issuer,sink,args.root_pin,args.start_grant,args.live_grant,args.case,args.marker)
class Endpoint:
    roles={u:u for u in (62022,62023,62024,62026)};handle=Service.handle
    def dispatch(self,r,uid):
        q.need(type(r) is dict and set(r)=={'op','args'} and type(r['args']) is dict,'RPC_SHAPE');op=r['op'];a=r['args']
        if op in ('execute_C','history_C'):
            if uid!=62026:raise Refused('C_ROLE')
        elif uid!=62022:raise Refused('CONTROL_ROLE')
        try:
            if op=='rearm_C':q.need(a=={},'REARM_ARGS');result=b.rearm()
            elif op=='issue_C':q.need(set(a)=={'challenge','ttl'},'ISSUE_ARGS');result=b.issue_C(**a)
            elif op=='execute_C':q.need(set(a)=={'permit','request'},'EXECUTE_ARGS');result=b.execute_C(uid=uid,**a)
            elif op=='history_C':q.need(a=={},'HISTORY_ARGS');result=b.history_C(uid)
            else:raise Refused('OP')
        except Refused:raise
        except InvalidSignature:raise Refused('SIGNATURE_INVALID')
        except (ValueError,OSError,sqlite3.Error) as e:raise Refused(str(e) if isinstance(e,ValueError) else 'AUTHORITY_UNAVAILABLE')
        except Exception:traceback.print_exc();raise
        return dict(result=result,receipt=signed(sink,RPC,dict(schema='FCI-C-NATIVE-EXECUTION-RPC/1',op=op,uid=uid,result_digest=q.digest(result),execution_policy=policy())))
try:
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);listener.bind(str(args.socket));args.socket.chmod(0o666);listener.listen(8)
        print(json.dumps(dict(pid=os.getpid(),identity=identity,normal_native_constructor_called=True,role_C_native=b.role_C_native,sink_public=public(sink),native_epoch=b.epoch())),flush=True)
        endpoint=Endpoint()
        while True:
            conn,_=listener.accept();endpoint.handle(conn)
finally:b.close()
