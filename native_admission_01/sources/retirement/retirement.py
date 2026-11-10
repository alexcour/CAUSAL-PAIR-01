"""Terminal capability retirement overlay; preserved native reservations are never erased.

Root/OS/single owner and retained authority are trusted. This is NOT LIFE01
CANCELLED, not a handoff certificate, and not a permission for generation C.
"""
import copy,hashlib,json,sqlite3,time,threading,uuid
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
import quiescence as q
DOMAIN=b'FCI-NATIVE-RETIREMENT/1\0'
def provision(path):
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE native_retirements(rid TEXT PRIMARY KEY,envelope TEXT NOT NULL)')
        db.execute('CREATE TABLE native_retirement_events(seq INTEGER PRIMARY KEY,event TEXT NOT NULL,rid TEXT NOT NULL,certificate_digest TEXT NOT NULL)')
def connect(path,readonly=False):return sqlite3.connect(Path(path).resolve().as_uri()+('?mode=ro' if readonly else '?mode=rw'),uri=True,isolation_level=None,timeout=10)
def decode(native_root,runtime,profile,prepared,db):
    """Frozen decoders and API objects with explicit connections; no startup/rearm."""
    from native_bridge import load_native,NativeBridge
    from certified_bridge import CertifiedBridge
    SqlService,Standard,auth=load_native(native_root)
    p=prepared['request_B']['permit']['body'];rid=p['native_operation_id']
    handles=[]
    if profile=='FCI':
        from fci_hardened.finalizing_consumer import FinalizingConsumer
        from fci_hardened.spend_ledger import SpendLedger,ticket_digest
        keys={k:bytes.fromhex(v) for k,v in json.loads((Path(runtime)/'keys.json').read_text()).items()}
        ledger=SpendLedger.__new__(SpendLedger);ledger.db=connect(Path(runtime)/'spend.db');handles.append(ledger.db)
        ledger.key=keys['spend'];ledger.scope=dict(instance='I',target='SIM_SINK',policy=p['policy'],context=prepared['request_B']['native']['authorization']['body']['context'])
        consumer=FinalizingConsumer.__new__(FinalizingConsumer)
        consumer.db=db;consumer.key=keys['effect'];consumer.token_key=keys['token'];consumer.receipt_key=keys['receipt'];consumer.rearm_key=keys['local_rearm'];consumer.instance='I';consumer.target='SIM_SINK';consumer.ledger=ledger
        state=consumer._state();entry=consumer._entry(rid);spend=ledger._read();fence=consumer._fence(rid)
        q.need(state.policy==p['policy'] and state.context==ledger.scope['context'],'AUTHENTICATED_CONSUMER_POLICY')
        q.need(entry is not None and ledger.lookup(rid) is not None,'NATIVE_B_REQUIRED')
        record=ledger.lookup(rid);q.need(record['kind']=='EFFECT_ATTEMPT' and record['ticket_digest']==ticket_digest(entry['ticket']),'RETAINED_NATIVE_RESERVATION_BINDING')
        operation=db.execute('SELECT ticket_digest,phase FROM d2_operations WHERE operation_id=?',(rid,)).fetchone()
        q.need(operation is not None and operation[0]==record['ticket_digest'],'NATIVE_OPERATION_TICKET')
        native=SqlService.__new__(SqlService);native.runtime=Path(runtime);native.consumer=consumer;native.public_key=bytes.fromhex(prepared['context']['issuer_public'])
        native.roles={62023:'requester',62024:'requester',62022:'maintainer'};native.policy=SimpleNamespace(digest=p['policy']);native.poisoned=True
        native._owner_thread=threading.get_ident();native._entry_lock=threading.RLock();native._active_request=False;native.request_id=rid;native._emit=lambda *a,**kw:None
        detail=dict(decoder='FROZEN_FCI_MAC_DECODERS_IN_TRUSTED_OWNER',consumer_status=entry['status'],native_phase=operation[1],
            reservation=record,spend_digest=q.digest(spend),ticket_digest=ticket_digest(entry['ticket']),fence=fence)
    else:
        native=Standard.__new__(Standard);native.db=db;native.ref=connect(Path(runtime)/'reference.db');handles.append(native.ref)
        native.cfg=json.loads((Path(runtime)/'public.json').read_text());native.key=bytes.fromhex(native.cfg['public_key'])
        native.owner=threading.get_ident();native.maybe_effect=False;native.provider=lambda:dict(flags=[True]*5,source_ok=True);native.now=lambda:int(time.monotonic());native.hook=lambda point:None
        q.need(native.cfg['deployment_id']==p['key']['deployment'] and native.cfg['policy_digest']==p['policy'],'STANDARD_INSTALLED_SCOPE')
        inspection=native.inspect(rid);phase=native.ref.execute('SELECT phase FROM attempts WHERE operation_id=?',(rid,)).fetchone()
        q.need(phase is not None,'STANDARD_NATIVE_B_REQUIRED')
        detail=dict(decoder='FROZEN_STANDARD_SIGNED_HISTORY',native_phase=phase[0],inspection=inspection,reservation_retained=True)
    keys=json.loads((Path(runtime)/'bridge-private.json').read_text())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as Key
    bridge=CertifiedBridge.__new__(CertifiedBridge);bridge.runtime=Path(runtime);bridge.profile=profile;bridge.path=str(Path(runtime)/('consumer.db' if profile=='FCI' else 'resource.db'))
    bridge.signer=Key.from_private_bytes(bytes.fromhex(keys['issuer']));bridge.sink_key=Key.from_private_bytes(bytes.fromhex(keys['sink']));bridge.auth=auth
    bridge.requesters={62023,62024};bridge.controller=62022;bridge.engine=native;bridge.db=db;bridge.active=None;bridge.policy=p['policy'];bridge.now=lambda:int(time.monotonic());bridge.guard_observations=[]
    bridge.table='demo_configuration' if profile=='FCI' else 'configuration';bridge.effects='demo_effects' if profile=='FCI' else 'effects';bridge.certificate_deployment=p['key']['deployment']
    return native,bridge,detail,handles
def project_preimage(stores,profile,rid):
    projected=copy.deepcopy(stores);main=projected[q.authority_names(profile)[0]]
    q.need(len(main['native_retirements']['rows'])==1 and len(main['native_retirement_events']['rows'])==1,'ONE_RETIREMENT_EVENT')
    main['native_retirements']['rows']=[];main['native_retirement_events']['rows']=[]
    table=main['sk_attempts'];idx=table['columns'].index('rid');state=table['columns'].index('state')
    matches=[r for r in table['rows'] if r[idx]==rid];q.need(len(matches)==1 and matches[0][state]=='FENCED','RETIRED_BUSINESS_FENCE');matches[0][state]='OPEN'
    return projected
class Retirement:
    def __init__(self,stage,runtime,profile,prepared,context,proof,sink,snapshot):
        self.stage,self.runtime,self.profile,self.prepared,self.context,self.proof,self.sink,self.snapshot=stage,Path(runtime),profile,prepared,context,proof,sink,snapshot
        self.path=self.runtime/q.authority_names(profile)[0];self.rid=prepared['request_B']['permit']['body']['native_operation_id']
    def stores(self):return self.snapshot(self.runtime,self.profile)['stores']
    def stored(self,db):
        row=db.execute('SELECT envelope FROM native_retirements WHERE rid=?',(self.rid,)).fetchone();return json.loads(row[0]) if row else None
    def verify_stored(self,env,stores):
        q.quiescence(self.context,self.proof,self.prepared)
        b=q.verify(env,self.context['sink_public'],DOMAIN)
        q.need(b['schema']=='FCI-NATIVE-RETIREMENT/1' and b['scope']==self.context['scope'] and b['termination_proof_digest']==q.digest(self.proof)
            and b['preimage_digest']==self.proof['body']['state_digest'] and b['disposition']=='CAPABILITY_RETIRED_NO_EFFECT'
            and b['retirement_policy_sha256']==hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            and b['legacy_native_state_preserved'] is True and b['handoff_authorized'] is b['execution_authorized'] is b['recovery_authorized'] is False,'RETIREMENT_CERTIFICATE_BINDING')
        files=q.inventory(self.runtime,self.profile);original=self.proof['body']['authority_inventory'];main=q.authority_names(self.profile)[0]
        q.need(set(files)==set(original) and all({k:v for k,v in item.items() if k!='sha256'}=={k:v for k,v in original[n].items() if k!='sha256'}
            and (n==main or item['sha256']==original[n]['sha256']) for n,item in files.items()),'RETAINED_AUTHORITY_IDENTITIES')
        q.need(q.digest(project_preimage(stores,self.profile,self.rid))==b['preimage_digest'],'ONLY_DECLARED_RETIREMENT_DELTA')
        return b
    def close(self,abort=False):
        before=self.stores();decision=q.decide(self.context,self.proof,self.prepared,before,q.inventory(self.runtime,self.profile))
        with closing(connect(self.path)) as db:
            db.execute('BEGIN IMMEDIATE')
            handles=[]
            try:
                old=self.stored(db)
                if old:
                    self.verify_stored(old,before);db.rollback();return dict(status='RETIREMENT_RETRIEVED',certificate=old,new_retirement=False,handoff_authorized=False)
                if decision['decision']=='HISTORICAL_RESULT_ONLY':db.rollback();return dict(status='HISTORICAL_RESULT_ONLY',decision=decision,new_retirement=False,handoff_authorized=False)
                q.need(decision['code']=='NATIVE_B_UNRESOLVED' and decision['quiescence']=='ATTESTED_TERMINATED_OWNER','RETIREMENT_INPUT_NOT_QUALIFIED')
                current=self.stores();q.need(current==before and q.digest(current)==self.proof['body']['state_digest'],'LOCKED_RETAINED_VIEW')
                native,bridge,detail,handles=decode(self.stage/'native',self.runtime,self.profile,self.prepared,db)
                if self.profile=='FCI':q.need(detail['consumer_status']=='PENDING' and detail['fence'] is None and detail['native_phase']=='PREPARED','FCI_PENDING_RESERVATION_ONLY')
                else:q.need(detail['inspection']['effect_status']=='UNKNOWN' and detail['native_phase']=='RESERVED','STANDARD_PENDING_RESERVATION_ONLY')
                body=dict(schema='FCI-NATIVE-RETIREMENT/1',retirement_id=uuid.uuid4().hex,scope=self.context['scope'],
                    termination_proof_digest=q.digest(self.proof),preimage_digest=q.digest(current),native_evidence=detail,
                    retirement_policy_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    disposition='CAPABILITY_RETIRED_NO_EFFECT',legacy_native_state_preserved=True,
                    handoff_authorized=False,execution_authorized=False,recovery_authorized=False,independent_attestation=False)
                env=q.signed(self.sink,DOMAIN,body)
                q.verify(env,self.context['sink_public'],DOMAIN)
                changed=db.execute("UPDATE sk_attempts SET state='FENCED' WHERE rid=? AND state='OPEN'",(self.rid,));q.need(changed.rowcount==1,'ONE_BUSINESS_FENCE')
                db.execute('INSERT INTO native_retirements VALUES(?,?)',(self.rid,q.canonical(env).decode()))
                db.execute('INSERT INTO native_retirement_events(event,rid,certificate_digest) VALUES(?,?,?)',('CAPABILITY_RETIRED',self.rid,q.digest(env)))
                q.need(db.in_transaction,'REAL_NATIVE_SQL_TRANSACTION')
                if abort:raise RuntimeError('INJECTED_RETIREMENT_BEFORE_COMMIT')
                db.commit();self.verify_stored(env,self.stores())
                return dict(status='CAPABILITY_RETIRED',certificate=env,new_retirement=True,handoff_authorized=False)
            except BaseException:
                if db.in_transaction:db.rollback()
                raise
            finally:
                for handle in handles:handle.close()
    def probes(self,uid):
        q.need(uid==62024,'B_ROLE');before=self.stores();answers=[]
        with closing(connect(self.path)) as db:
            env=self.stored(db);retired=env is not None
            if retired:self.verify_stored(env,before)
            else:
                decision=q.decide(self.context,self.proof,self.prepared,before,q.inventory(self.runtime,self.profile))
                q.need(decision['decision']=='HISTORICAL_RESULT_ONLY','NO_RETIREMENT_REQUIRES_HISTORICAL_RESULT')
                return dict(retired=False,historical_result_verified=True,guarded_routes=[],frozen_routes=[],legacy_redeem_probe=None,
                    native_decoder=None,normal_service_constructor_called=False,rearm_called=False,allocation_C_created=False)
            native,bridge,detail,handles=decode(self.stage/'native',self.runtime,self.profile,self.prepared,db)
            from native_bridge import NativeBridge
            from certified_bridge import CertifiedBridge
            try:
                def guarded(name,fn):
                    if retired:
                        self.verify_stored(env,self.stores());value=dict(code='BLOCK_NATIVE_RETIRED',new_effect=False)
                    else:value=fn()
                    answers.append(dict(route=name,result=value))
                guarded('bridge_execute',lambda:NativeBridge.execute(bridge,self.prepared['request_B'],uid))
                guarded('native_execute',lambda:native.execute(uid,self.prepared['request_B']['native']))
                if self.profile=='FCI':
                    entry=native.consumer._entry(self.rid);ticket=entry['ticket']
                    guarded('native_handle_finish',lambda:native.handle(uid,q.canonical(dict(op='finish',request_id=self.rid))))
                    guarded('consumer_finish',lambda:dict(code=native.consumer.finish(self.rid,None,lambda:int(time.monotonic()),lambda:(True,)*5).code))
                    guarded('consumer_receive',lambda:dict(code=native.consumer.receive(ticket,None,int(time.monotonic())).code))
                    guarded('consumer_cancel',lambda:dict(code=native.consumer.cancel(ticket,int(time.monotonic())).code))
                raw=[]
                try:raw.append(dict(route='frozen_bridge_execute',result=NativeBridge.execute(bridge,self.prepared['request_B'],uid)))
                except bridge.auth.AuthorizationRefused as exc:raw.append(dict(route='frozen_bridge_execute',code=str(exc)))
                raw.append(dict(route='frozen_native_execute',result=native.execute(uid,self.prepared['request_B']['native'])))
                if self.profile=='FCI':
                    raw.append(dict(route='frozen_consumer_finish',code=native.consumer.finish(self.rid,None,lambda:int(time.monotonic()),lambda:(True,)*5).code))
                c_probe=None
                if retired:
                    try:CertifiedBridge.redeem(bridge,env,62022);raise RuntimeError('RETIREMENT_USED_AS_HANDOFF')
                    except ValueError as exc:c_probe=dict(accepted=False,error=type(exc).__name__)
                after=self.stores();q.need(before==after,'PROBES_WRITE_NO_STATE')
                return dict(retired=retired,guarded_routes=answers,frozen_routes=raw,legacy_redeem_probe=c_probe,
                    native_decoder=detail,normal_service_constructor_called=False,rearm_called=False,allocation_C_created=False)
            finally:
                for handle in handles:handle.close()
