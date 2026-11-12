"""Versioned FCI composition: application staging after frozen finalizers.

PolicyStop deliberately escapes frozen Exception->UNKNOWN handlers BEFORE the
vendor COMMIT call. Only a verified rollback may turn it into an exact refusal.
Other exceptions and native UNKNOWN replies retain their original semantics.
"""
import json,sqlite3,threading,time
from contextlib import closing
from pathlib import Path
from native_bridge import NativeBridge,load_native
from snapshots import scalar
import quiescence as q

class PolicyStop(BaseException):
    def __init__(self,code,stage):self.code=code;self.stage=stage;super().__init__(code)
class RollbackUnresolved(BaseException):pass

def logical_main(db):
    result={}
    for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall():
        name='"'+table.replace('"','""')+'"'
        result[table]=dict(columns=[r[1] for r in db.execute('PRAGMA table_info('+name+')')],rows=[[scalar(v) for v in row] for row in db.execute('SELECT * FROM '+name+' ORDER BY 1')])
    return result

def policy_call(fn,stage):
    try:return fn()
    except ValueError as e:
        if str(e) in ('C_PERMIT_EXPIRED','C_REVOKED'):raise PolicyStop(str(e),stage) from e
        raise

class FinalizedSqlMixin:
    def __init__(self,*args,bridge,**kwargs):
        self.bridge=bridge;self.pending_sql=None;self.native_tx_before=None;self.native_commit_seen=False
        super().__init__(*args,**kwargs)
    def execute(self,uid,req):
        self.bridge.require(self.bridge.active is not None and uid==62026,'BRIDGE_CONTEXT_REQUIRED')
        self.pending_sql=None;self.native_tx_before=None;self.native_commit_seen=False
        return super().execute(uid,req)
    def capture(self,kind,data,raw,service):
        finish=data.get('operation')=='finish'
        if kind=='tx_begin' and finish:
            self.bridge.require(service.consumer.db.in_transaction,'NATIVE_TX_BEGIN')
            self.native_tx_before=logical_main(service.consumer.db)
        if kind=='tx_stage' and finish and raw.get('result_new_effect'):
            self.bridge.require(self.bridge.active is not None,'BRIDGE_CONTEXT_REQUIRED')
            before=policy_call(lambda:self.bridge.admit(service.consumer.db,*self.bridge.active),'admit')
            self.pending_sql=(data,raw,service,before)
            self.record('application_stage_deferred',source='VERSIONED_AFTER_NATIVE_FINALIZERS')
            return
        super().capture(kind,data,raw,service)
        if kind=='tx_commit' and finish:
            self.native_commit_seen=True;self.bridge.fault('after_commit')
    def _dispatch(self,op,req):
        if op!='finish':return super()._dispatch(op,req)
        entry=self.consumer._entry(req['request_id'])
        if entry is None or entry['status']!='PENDING':return super()._dispatch(op,req)
        from fci_hardened.service import clock
        level=entry['ticket']['token']['body']['action']['value']
        action=next((name for name,value in self.levels.items() if value==level),None)
        if action is None:return dict(code='BLOCK_ACTION')
        return self._result(self.consumer.finish(req['request_id'],self.anchor,clock,lambda:self._flags(action),hook=self.after_finalizers))
    def after_finalizers(self,point):
        if point!='after_commit_fence' or self.pending_sql is None:return
        data,raw,service,before=self.pending_sql;rid=self.active['operation']['operation_id']
        entry=self.consumer._entry(rid);fence=self.consumer._fence(rid)
        # A native denial never stages an application effect.
        if entry is None or entry['status']!='DONE' or fence is None or fence['decision']!='COMMIT_FENCE_PASS':return
        self.bridge.require(self.consumer.db.in_transaction and not self.native_commit_seen,'BEFORE_NATIVE_COMMIT')
        self.bridge.native_finalizations.append(dict(rid=rid,decision=fence['decision'],checked_at=fence['checked_at'],in_native_transaction=True))
        # Frozen SqlService stages its bound SQL intent only now, after all REF3 checks.
        super().capture('tx_stage',data,raw,service)
        policy_call(lambda:self.bridge.finish(self.consumer.db,*self.bridge.active,before),'finish')
        self.pending_sql=None;self.bridge.fault('before_commit')

class FinalizedBridge(NativeBridge):
    def __init__(self,root,runtime,profile,signer,sink_key,*,successor=62026,requester=62023,controller=62022,now=None,fault=lambda _:None):
        if profile!='FCI':
            super().__init__(root,runtime,profile,signer,sink_key,successor=successor,requester=requester,controller=controller,now=now,fault=fault);return
        SqlService,Standard,self.auth=load_native(root)
        self.profile=profile;self.runtime=Path(runtime);self.signer=signer;self.sink_key=sink_key
        self.requesters={requester,successor};self.controller=controller;self.now=now or (lambda:int(time.monotonic()));self.fault=fault
        self.active=None;self.guard_observations=[]
        class NormalFinalizedService(FinalizedSqlMixin,SqlService):pass
        self.engine=NormalFinalizedService(self.runtime,journal=self.runtime/'native-journal.jsonl',bridge=self)
        self.engine.roles[successor]='requester';self.db=self.engine.consumer.db
        self.table='demo_configuration';self.effects='demo_effects';self.policy=self.engine.policy.digest
        self.path=next(r[2] for r in self.db.execute('PRAGMA database_list') if r[1]=='main')
        self.require(self.db.execute('SELECT schema,policy FROM sk_control WHERE id=1').fetchone()==('SAME-K-NATIVE-BRIDGE/1',self.policy),'LEDGER_CONFIG')
        self.pending_before=None

def verified_rollback(engine,path):
    q.need(engine.native_tx_before is not None and not engine.native_commit_seen and engine.consumer.db.in_transaction,'NO_PROVEN_PRECOMMIT_ABORT')
    before=engine.native_tx_before
    engine.consumer.db.rollback()
    q.need(not engine.consumer.db.in_transaction,'ROLLBACK_NOT_RESOLVED')
    with closing(sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,isolation_level=None)) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN');after=logical_main(db);db.rollback()
    q.need(after==before,'ROLLBACK_DURABLE_VIEW_CHANGED')
    return before,after
