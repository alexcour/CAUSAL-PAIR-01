"""Explicit normal native startup, supervised fixture rearm and atomic C permit use.

New research composition. Root/OS/owner, retained stores and no clones are trusted.
The clock is sampled at final staging; elapsed time through COMMIT is not bounded.
"""
import hashlib,json,os,sys,time
from pathlib import Path
from native_bridge import RESULT
from native_finalization import FinalizedBridge,PolicyStop,RollbackUnresolved,verified_rollback
from handoff import public,signed,verify,canonical,key_text
from snapshots import root_snapshot
import quiescence as q
from capability import SAMPLED,require_capability,descriptor

GRANT=b'FCI-C-NATIVE-TRANSITION-GRANT/1\0'
PERMIT=b'FCI-C-NATIVE-CONSUMABLE-PERMIT/2\0'
RPC=b'FCI-C-NATIVE-EXECUTION-RPC/2\0'
ABORT=b'FCI-C-VERIFIED-PRECOMMIT-ROLLBACK/1\0'

def policy():
    root=Path(__file__).resolve().parent
    return q.digest(dict(schema='FCI-C-EXECUTION-POLICY/3',files={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('execution.py','native_finalization.py','capability.py','owner.py')}))
def provision(path):
    import sqlite3
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE c_execution_permits(challenge TEXT PRIMARY KEY,envelope TEXT NOT NULL,request TEXT NOT NULL)')
        db.execute('CREATE TABLE c_permit_consumptions(challenge TEXT PRIMARY KEY,permit_digest TEXT NOT NULL,rid TEXT UNIQUE NOT NULL,result_digest TEXT NOT NULL,checked_tick INTEGER NOT NULL)')
        db.execute('CREATE TABLE c_policy_aborts(seq INTEGER PRIMARY KEY,envelope TEXT NOT NULL)')

def persist_permit_and_read_grant(db,challenge,wrapper,request,allocation):
    q.need(db.in_transaction and allocation['uid']==62026,'C_PERMIT_READ_GRANT_TRANSACTION')
    db.execute('INSERT INTO c_execution_permits VALUES(?,?,?)',(challenge,canonical(wrapper).decode(),canonical(request).decode()))
    db.execute('INSERT OR IGNORE INTO sk_readers VALUES(?,?)',(key_text(allocation['key']),62026))

def root_grant(path,pin,purpose,runtime,profile,*,exact=False):
    path=Path(path)
    for p in (path,path.parent):
        s=p.lstat();q.need(s.st_uid==0 and not s.st_mode&0o022 and not p.is_symlink(),'TRANSITION_ROOT_BOUNDARY')
    env=json.loads(path.read_text());g=verify(env,pin,GRANT)
    q.need(g['schema']=='FCI-C-NATIVE-TRANSITION-GRANT/1' and g['purpose']==purpose and g['execution_policy']==policy(),'TRANSITION_GRANT_BINDING')
    q.need(g['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip() and g['not_before']<=int(time.monotonic())<g['not_after'],'TRANSITION_GRANT_EXPIRED')
    inv=q.inventory(runtime,profile);q.need(set(inv)==set(g['inventory']),'TRANSITION_AUTHORITY_MISSING')
    for n,x in inv.items():
        y=g['inventory'][n];q.need({k:v for k,v in x.items() if k!='sha256'}=={k:v for k,v in y.items() if k!='sha256'} and (not exact or x==y),'TRANSITION_AUTHORITY_CHANGED')
    if exact:q.need(q.digest(root_snapshot(runtime,profile)['stores'])==g['state_digest'],'TRANSITION_STATE_CHANGED')
    return env,g

class Execution(FinalizedBridge):
    def __init__(self,stage,runtime,profile,issuer,sink,pin,start_grant,live_grant,case,marker):
        self.root_pin=pin;self.live_grant=Path(live_grant);self.case=case;self.marker=Path(marker);self.wrapper=None
        self.final_checks=[];self.check_failures=[];self.native_finalizations=[];self.execute_entry_calls=0;self.rearm_calls=0
        _,g=root_grant(start_grant,pin,'STARTUP',runtime,profile,exact=True)
        w=g['owner_wait'];q.need(w['waited'] is True and w['exit'] in (-15,-9) and w['pid']!=os.getpid(),'PREVIOUS_OWNER_WAITED')
        cert=verify(g['activation'],public(sink),b'FCI-C-ACTIVATION/1\0');self.allocation=cert['allocation'];self.activation=g['activation']
        q.need(self.allocation['uid']==62026 and self.allocation['generation']==3,'C_SCOPE')
        self.expected_scope=g['scope'];self.initial_start_grant=g
        # Real constructor calls, including lifetime lock and STARTUP mutations.
        super().__init__(stage/'native',runtime,profile,issuer,sink,successor=62026,fault=self.cut)
        self.require(self.allocation['key']==g['scope']['key'] and self.allocation['h']==g['scope']['h'],'STARTUP_BUSINESS_SCOPE')
        self.require(self.db.execute('SELECT envelope FROM c_activations WHERE rid=?',(self.allocation['rid'],)).fetchone()==(canonical(self.activation).decode(),),'RETAINED_ACTIVATION')
        # Explicit C role extension: FCI constructor adapter installs this native role.
        # Standard's signed execute validates the actual UID; this facade admits only C.
        self.role_C_native=(self.engine.roles.get(62026)=='requester') if profile=='FCI' else 'SIGNED_STANDARD_UID_AND_VERSIONED_FACADE'

    def epoch(self):return self.engine.meta()['epoch'] if self.profile=='FCI' else self.engine.control()[0]
    def grant(self,purpose,exact=False):
        env,g=root_grant(self.live_grant,self.root_pin,purpose,self.runtime,self.profile,exact=exact)
        self.require(g['owner_pid']==os.getpid() and g['scope']==self.expected_scope and g['activation']==self.activation,'EXECUTION_OWNER_OR_SCOPE')
        return env,g
    def rearm(self):
        self.grant('REARM',exact=True)
        from recovery import safe_rearm
        self.rearm_calls+=1;return safe_rearm(self,62022)
    def capabilities_C(self):return descriptor()
    def issue_C(self,challenge,ttl,required_capability):
        require_capability(required_capability)
        env,g=self.grant('EXECUTE',exact=True)
        self.require(type(challenge) is str and len(challenge)==32 and type(ttl) is int and 1<=ttl<=25,'C_ISSUE_PARAMETERS')
        self.require(self.epoch()==g['native_epoch'],'C_NATIVE_EPOCH')
        request=self.issue(self.allocation,62022,ttl)
        p=request['permit']['body'];self.require(p['not_after']<=g['not_after'],'C_PERMIT_EXCEEDS_GRANT')
        wrapper=signed(self.sink_key,PERMIT,dict(schema='FCI-C-NATIVE-CONSUMABLE-PERMIT/2',challenge=challenge,request_digest=q.digest(request),
            grant_digest=q.digest(env),activation_digest=q.digest(self.activation),allocation=self.allocation,execution_policy=policy(),
            owner_pid=os.getpid(),native_epoch=self.epoch(),boot_id=g['boot_id'],not_before=p['not_before'],not_after=p['not_after'],temporal_capability=SAMPLED))
        with self.open_control() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                self.require(not db.execute('SELECT 1 FROM c_execution_permits').fetchone(),'ONE_EXECUTION_PERMIT')
                persist_permit_and_read_grant(db,challenge,wrapper,request,self.allocation);db.commit()
            finally:
                if db.in_transaction:db.rollback()
        return dict(permit=wrapper,request=request,required_capability=SAMPLED)
    def check_C(self,db,permit,request,uid,stage='precheck'):
        try:return self._check_C(db,permit,request,uid)
        except Exception as e:
            # Fixture diagnostic only: preserve the original exception and native verdict.
            event=dict(stage=stage,error_type=type(e).__name__,code=str(e),in_native_transaction=db.in_transaction)
            self.check_failures.append(event)
            print(json.dumps(dict(C_check_failure=event)),file=sys.stderr,flush=True)
            raise
    def _check_C(self,db,permit,request,uid):
        self.require(uid==62026,'C_ROLE');env,g=self.grant('EXECUTE')
        b=verify(permit,public(self.sink_key),PERMIT)
        self.require(b['schema']=='FCI-C-NATIVE-CONSUMABLE-PERMIT/2' and b['grant_digest']==q.digest(env) and b['activation_digest']==q.digest(self.activation)
            and b['allocation']==self.allocation and b['request_digest']==q.digest(request) and b['execution_policy']==policy()
            and b.get('temporal_capability')==SAMPLED and b['owner_pid']==os.getpid() and b['native_epoch']==self.epoch()==g['native_epoch'] and b['boot_id']==g['boot_id'],'C_PERMIT_BINDING')
        tick=int(time.monotonic());self.require(b['not_before']<=tick<b['not_after'],'C_PERMIT_EXPIRED')
        self.require(db.execute('SELECT envelope,request FROM c_execution_permits WHERE challenge=?',(b['challenge'],)).fetchone()==(canonical(permit).decode(),canonical(request).decode()),'C_PERMIT_NOT_DURABLE')
        self.require(db.execute('SELECT status FROM c_activations WHERE rid=?',(self.allocation['rid'],)).fetchone()==('ACTIVE',),'C_REVOKED')
        self.check(db,request,uid)
        return b,tick
    def admit(self,db,request,uid):
        self.require(self.wrapper is not None,'C_WRAPPER_CONTEXT_REQUIRED')
        self.check_C(db,self.wrapper,request,uid,stage='admit')
        return super().admit(db,request,uid)
    def finish(self,db,request,uid,before):
        super().finish(db,request,uid,before)
        # Check after native and bridge effect staging, inside the actual effect txn.
        b,tick=self.check_C(db,self.wrapper,request,uid,stage='finish')
        self.require(not db.execute('SELECT 1 FROM c_permit_consumptions WHERE challenge=?',(b['challenge'],)).fetchone(),'C_PERMIT_CONSUMED')
        result=json.loads(self.business(db,key_text(b['allocation']['key']),b['allocation']['h'])[2])
        db.execute('INSERT INTO c_permit_consumptions VALUES(?,?,?,?,?)',(b['challenge'],q.digest(self.wrapper),self.allocation['rid'],q.digest(result),tick))
        self.final_checks.append(dict(in_native_transaction=db.in_transaction,tick=tick,deadline=b['not_after'],permit_digest=q.digest(self.wrapper)))
    def cut(self,point):
        if point=='before_commit' and self.case in ('expired_before_commit','expired_before_commit_kill'):
            # Trusted fixture hook AFTER final sample and consumption staging.
            with self.marker.open('w') as out:
                out.write(json.dumps(dict(pid=os.getpid(),uid=os.geteuid(),point=point,
                    tick=time.monotonic(),deadline=self.wrapper['body']['not_after'])));out.flush();os.fsync(out.fileno())
            release=self.marker.with_suffix('.release')
            while not release.exists():time.sleep(.01)
            return
        if self.case==point:
            with self.marker.open('w') as out:
                out.write(json.dumps(dict(pid=os.getpid(),uid=os.geteuid(),point=point)));out.flush();os.fsync(out.fileno())
            while True:time.sleep(.05)
    def execute_C(self,permit,request,uid,required_capability):
        self.require(uid==62026,'C_ROLE');require_capability(required_capability)
        with self.open_control() as db:self.check_C(db,permit,request,uid)
        self.wrapper=permit
        def after():
            if self.case=='expired_after_precheck':
                deadline=permit['body']['not_after']
                while int(time.monotonic())<deadline:time.sleep(.02)
            elif self.case=='revoked_after_precheck':
                with self.open_control() as db:
                    db.execute('BEGIN IMMEDIATE')
                    db.execute("UPDATE sk_attempts SET state='FENCED' WHERE rid=?",(self.allocation['rid'],))
                    db.execute("UPDATE c_activations SET status='REVOKED' WHERE rid=?",(self.allocation['rid'],))
                    db.execute('UPDATE sk_control SET epoch=epoch+1 WHERE id=1');db.commit()
        try:
            self.execute_entry_calls+=1;v=super().execute(request,uid,after_precheck=after)
            return dict(temporal_capability=SAMPLED,commit_deadline_qualified=False,response=v,final_checks=list(self.final_checks),execute_entry_calls=self.execute_entry_calls,check_failures=list(self.check_failures),native_finalizations=list(self.native_finalizations))
        except PolicyStop as stop:
            # This is a new typed pre-COMMIT path. No native UNKNOWN verdict exists
            # on this path; every ordinary native UNKNOWN still returns unchanged.
            try:
                self.require(self.profile=='FCI' and stop.code in ('C_PERMIT_EXPIRED','C_REVOKED') and stop.stage in ('admit','finish'),'TYPED_POLICY_STOP_ONLY')
                before,after=verified_rollback(self.engine,self.path)
                body=dict(schema='FCI-C-VERIFIED-PRECOMMIT-ROLLBACK/1',code=stop.code,stage=stop.stage,uid=uid,rid=self.allocation['rid'],
                    request_digest=q.digest(request),permit_digest=q.digest(permit),execution_policy=policy(),before=before,
                    before_digest=q.digest(before),after_digest=q.digest(after),commit_boundary='BEFORE_VENDOR_COMMIT_CALL',
                    native_verdict=None,rollback_verified=True,readback='SEPARATE_READ_ONLY_CONNECTION',boot_id=permit['body']['boot_id'])
                receipt=signed(self.sink_key,ABORT,body)
                with self.open_control() as db:
                    db.execute('BEGIN IMMEDIATE')
                    try:db.execute('INSERT INTO c_policy_aborts(envelope) VALUES(?)',(canonical(receipt).decode(),));db.commit()
                    finally:
                        if db.in_transaction:db.rollback()
            except Exception as error:
                raise RollbackUnresolved('PRECOMMIT_ABORT_NOT_ATTESTED') from error
            self.require(False,stop.code)
        finally:self.wrapper=None
    def abort_receipts(self):
        with self.open_control() as db:return [json.loads(r[0]) for r in db.execute('SELECT envelope FROM c_policy_aborts ORDER BY seq')]
    def history_C(self,uid):
        self.require(uid==62026,'C_ROLE');a=self.allocation
        with self.open_control() as db:
            rows=db.execute('SELECT challenge,permit_digest,rid,result_digest,checked_tick FROM c_permit_consumptions').fetchall()
            value=self.business(db,key_text(a['key']),a['h'])[2]
            if value is None:
                self.require(not rows,'ORPHAN_C_CONSUMPTION');return dict(status='HOLD_NO_C_RESULT',execution_authorized=False,temporal_capability=SAMPLED,commit_deadline_qualified=False)
            self.require(len(rows)==1,'ONE_C_CONSUMPTION')
            record=rows[0];p=db.execute('SELECT envelope,request FROM c_execution_permits WHERE challenge=?',(record[0],)).fetchone()
            self.require(p is not None,'C_DURABLE_PERMIT_MISSING');permit=json.loads(p[0]);request=json.loads(p[1]);b=verify(permit,public(self.sink_key),PERMIT)
            self.require(record[1:]==(q.digest(permit),a['rid'],q.digest(json.loads(value)),record[4]) and b['not_before']<=record[4]<b['not_after']
                and b['allocation']==a and b['request_digest']==q.digest(request) and b.get('temporal_capability')==SAMPLED and b['execution_policy']==policy(),'C_CONSUMPTION_BINDING')
        result=self.read_result(a['key'],a['h'],uid)
        native=self.engine.inspect_operation(a['rid']) if self.profile=='FCI' else self.engine.inspect(a['rid'])
        self.require(native['effect_status']=='COMMITTED_PROVEN','NATIVE_C_HISTORY')
        return dict(status='C_RESULT_RETRIEVED',temporal_capability=SAMPLED,commit_deadline_qualified=False,result=result,native=native,new_effect=False,consumption=list(record))
