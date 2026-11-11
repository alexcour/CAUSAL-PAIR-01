"""Versioned activation/permit gate; no business/native execute or rearm call."""
import copy,hashlib,json,time
from pathlib import Path
from contextlib import closing
import quiescence as q
import admission as a
from retirement import connect,decode
GRANT=b'FCI-C-ACTIVATION-GRANT/1\0';CERT=b'FCI-C-ACTIVATION/1\0';PERMIT=b'FCI-C-EXECUTION-PERMIT/1\0';RPC=b'FCI-C-ACTIVATION-RPC/1\0'
def policy():return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
def provision(path):
    with closing(connect(path)) as db:
        db.execute('CREATE TABLE c_activations(rid TEXT PRIMARY KEY,envelope TEXT NOT NULL,status TEXT NOT NULL)')
        db.execute('CREATE TABLE c_permits(challenge TEXT PRIMARY KEY,envelope TEXT NOT NULL,request TEXT NOT NULL)')
        db.execute('CREATE TABLE c_activation_events(seq INTEGER PRIMARY KEY,event TEXT NOT NULL,digest TEXT NOT NULL)')
class Activation:
    def __init__(self,retirement,admission_grant,grant):self.r=retirement;self.admission=a.Admission(retirement,admission_grant);self.path=Path(grant)
    def grant(self):
        for p in (self.path,self.path.parent):
            s=p.lstat();q.need(s.st_uid==0 and not s.st_mode&0o022 and not p.is_symlink(),'ROOT_ACTIVATION_GRANT')
        env=json.loads(self.path.read_text());g=q.verify(env,self.r.context['supervisor_public'],GRANT)
        fields={'schema','grant_id','scope','admission_digest','state_digest','inventory','control','activation_policy','owner_wait','boot_id','not_before','not_after'}
        q.need(set(g)==fields and g['schema']=='FCI-C-ACTIVATION-GRANT/1' and g['scope']==self.r.context['scope']
            and g['activation_policy']==policy() and type(g['grant_id']) is str and len(g['grant_id'])==32,'ACTIVATION_GRANT_BINDING')
        w=g['owner_wait'];q.need(w['waited'] is True and w['exit']==-15 and type(w['pid']) is int and w['pid']>0,'ADMISSION_OWNER_WAITED')
        now=int(time.monotonic());q.need(g['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'ACTIVATION_BOOT')
        q.need(type(g['not_before']) is type(g['not_after']) is int and g['not_before']<=now<g['not_after']<=g['not_before']+180,'ACTIVATION_GRANT_EXPIRED')
        q.need(type(g['control']) is list and len(g['control'])==3 and g['control'][2]==0,'ACTIVATION_CONTROL_GRANT')
        return env,g
    def inventory(self,g,changed):
        current=q.inventory(self.r.runtime,self.r.profile);orig=g['inventory'];main=q.authority_names(self.r.profile)[0]
        q.need(set(current)==set(orig)==set(q.authority_names(self.r.profile)),'ACTIVATION_AUTHORITY_MISSING')
        for n,x in current.items():
            q.need({k:v for k,v in x.items() if k!='sha256'}=={k:v for k,v in orig[n].items() if k!='sha256'}
                and (changed and n==main or x['sha256']==orig[n]['sha256']),'ACTIVATION_AUTHORITY_CHANGED')
    def baseline(self,stores,g,active):
        s=copy.deepcopy(stores);m=s[q.authority_names(self.r.profile)[0]]
        if active:
            q.need(len(m['c_activations']['rows'])==1,'ONE_C_ACTIVATION')
            for n in ('c_activations','c_permits','c_activation_events'):m[n]['rows']=[]
            t=m['sk_attempts'];rows=[x for x in t['rows'] if x[t['columns'].index('g')]==3];q.need(len(rows)==1,'ONE_C')
            state=t['columns'].index('state');q.need(rows[0][state] in ('OPEN','FENCED'),'ACTIVE_OR_REVOKED_C');revoked=rows[0][state]=='FENCED';rows[0][state]='ADMISSION_ONLY'
            t=m['sk_control'];row=t['rows'][0];idx=t['columns'].index('epoch')
            q.need(row[idx]==g['control'][1]+int(revoked),'C_CONTROL_EPOCH');row[idx]-=int(revoked)
        q.need(q.digest(s)==g['state_digest'],'ACTIVATION_BASELINE_CHANGED');return s
    def existing(self,db):
        row=db.execute('SELECT rid,envelope,status FROM c_activations').fetchone()
        if row:
            env=json.loads(row[1]);b=q.verify(env,self.r.context['sink_public'],CERT)
            q.need(b['schema']=='FCI-C-ACTIVATION/1' and b['activation_policy']==policy() and b['allocation']['rid']==row[0],'DURABLE_ACTIVATION_CERT')
            return row,env,b
        return None
    def view(self,db,grant,g):
        old=self.existing(db);self.inventory(g,bool(old));stores=self.r.stores();base=self.baseline(stores,g,bool(old))
        main=q.authority_names(self.r.profile)[0];records=q.rows(base,main,'native_admissions');q.need(len(records)==1,'ADMITTED_C_REQUIRED')
        adm=json.loads(records[0]['envelope']);b=q.verify(adm,self.r.context['sink_public'],a.RECEIPT);allocation=b['allocation']
        q.need(q.digest(adm)==g['admission_digest'] and allocation['generation']==3 and allocation['uid']==62026
            and b['execution_authorized'] is b['recovery_authorized'] is b['native_permit_issued'] is False,'SIGNED_C_ADMISSION')
        original_grant,ag=self.admission.grant();q.need(b['grant_digest']==q.digest(original_grant) and q.digest(a.project(base,self.r.profile,allocation))==ag['state_digest'],'ADMISSION_PREIMAGE_LINK')
        retired=self.r.stored(db);self.r.verify_stored(retired,a.project(base,self.r.profile,allocation))
        q.need(b['retirement_digest']==q.digest(retired),'RETIRED_PREDECESSOR_LINK')
        if old:q.need(old[2]==dict(schema='FCI-C-ACTIVATION/1',grant_digest=q.digest(grant),admission_digest=q.digest(adm),allocation=allocation,
            activation_policy=policy(),execution_route='VERSIONED_PERMIT_GATE',native_execution_qualified=False),'EXACT_ACTIVATION_CERT')
        control=list(db.execute('SELECT policy,epoch,revoked FROM sk_control WHERE id=1').fetchone())
        q.need(control[0]==g['control'][0] and control[2]==0,'CURRENT_POLICY_REVOKED')
        return old,allocation,control
    def activate(self,abort=False):
        grant,g=self.grant()
        with closing(connect(self.r.path)) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                old,allocation,control=self.view(db,grant,g)
                if old:
                    q.need(old[0][2]=='ACTIVE','C_REVOKED');db.rollback();return dict(status='ACTIVATION_RETRIEVED',certificate=old[1],new_activation=False)
                q.need(control==g['control'],'ACTIVATION_CONTROL_CHANGED')
                changed=db.execute("UPDATE sk_attempts SET state='OPEN' WHERE rid=? AND state='ADMISSION_ONLY'",(allocation['rid'],));q.need(changed.rowcount==1,'ACTIVATE_EXACTLY_C')
                env=q.signed(self.r.sink,CERT,dict(schema='FCI-C-ACTIVATION/1',grant_digest=q.digest(grant),admission_digest=g['admission_digest'],
                    allocation=allocation,activation_policy=policy(),execution_route='VERSIONED_PERMIT_GATE',native_execution_qualified=False))
                db.execute("INSERT INTO c_activations VALUES(?,?,'ACTIVE')",(allocation['rid'],q.canonical(env).decode()))
                db.execute('INSERT INTO c_activation_events(event,digest) VALUES(?,?)',('C_ACTIVATED',q.digest(env)))
                if abort:raise RuntimeError('INJECTED_ACTIVATION_ABORT')
                db.commit();return dict(status='C_ACTIVATED',certificate=env,new_activation=True)
            except BaseException:
                if db.in_transaction:db.rollback()
                raise
    def issue(self,challenge,ttl):
        q.need(type(challenge) is str and len(challenge)==32 and all(c in '0123456789abcdef' for c in challenge),'CHALLENGE')
        q.need(type(ttl) is int and 1<=ttl<=25,'PERMIT_TTL')
        grant,g=self.grant()
        with closing(connect(self.r.path)) as db:
            db.execute('BEGIN IMMEDIATE');handles=[]
            try:
                old,allocation,control=self.view(db,grant,g);q.need(old is not None and old[0][2]=='ACTIVE','C_NOT_ACTIVE')
                stored=db.execute('SELECT envelope,request FROM c_permits WHERE challenge=?',(challenge,)).fetchone()
                if stored:
                    env=json.loads(stored[0]);q.need(env['body']['ttl']==ttl,'CHALLENGE_PARAMETERS_CHANGED')
                    q.need(int(time.monotonic())<env['body']['not_after'],'PERMIT_EXPIRED');db.rollback()
                    return dict(status='PERMIT_RETRIEVED',permit=env,request=json.loads(stored[1]),new_permit=False)
                native,bridge,detail,handles=decode(self.r.stage/'native',self.r.runtime,self.r.profile,self.r.prepared,db)
                bridge.requesters={62023,62024,62026}
                request=bridge.issue(allocation,62022,ttl=ttl);p=request['permit']['body']
                q.need(p['not_after']<=g['not_after'],'PERMIT_EXCEEDS_GRANT')
                env=q.signed(self.r.sink,PERMIT,dict(schema='FCI-C-EXECUTION-PERMIT/1',challenge=challenge,ttl=ttl,
                    grant_digest=q.digest(grant),activation_digest=q.digest(old[1]),allocation=allocation,request_digest=q.digest(request),
                    epoch=control[1],policy=control[0],boot_id=g['boot_id'],not_before=p['not_before'],not_after=p['not_after'],
                    activation_policy=policy(),route='VERSIONED_PERMIT_GATE'))
                db.execute('INSERT INTO c_permits VALUES(?,?,?)',(challenge,q.canonical(env).decode(),q.canonical(request).decode()))
                db.execute('INSERT INTO c_activation_events(event,digest) VALUES(?,?)',('C_PERMIT_ISSUED',q.digest(env)));db.commit()
                return dict(status='PERMIT_ISSUED',permit=env,request=request,new_permit=True)
            except BaseException:
                if db.in_transaction:db.rollback()
                raise
            finally:
                for h in handles:h.close()
    def authorize(self,permit,request,uid):
        q.need(type(uid) is int and uid==62026,'C_ROLE');grant,g=self.grant()
        with closing(connect(self.r.path)) as db:
            db.execute('BEGIN IMMEDIATE');handles=[]
            try:
                old,allocation,control=self.view(db,grant,g);q.need(old is not None and old[0][2]=='ACTIVE','C_REVOKED')
                p=q.verify(permit,self.r.context['sink_public'],PERMIT)
                q.need(p['grant_digest']==q.digest(grant) and p['activation_digest']==q.digest(old[1]) and p['allocation']==allocation
                    and p['request_digest']==q.digest(request) and p['epoch']==control[1] and p['policy']==control[0]
                    and p['activation_policy']==policy() and p['route']=='VERSIONED_PERMIT_GATE' and p['boot_id']==g['boot_id'],'PERMIT_BINDING')
                q.need(type(p['not_before']) is type(p['not_after']) is int and p['not_before']<=int(time.monotonic())<p['not_after'],'PERMIT_EXPIRED')
                row=db.execute('SELECT envelope,request FROM c_permits WHERE challenge=?',(p['challenge'],)).fetchone()
                q.need(row==(q.canonical(permit).decode(),q.canonical(request).decode()),'PERMIT_NOT_DURABLE')
                native,bridge,detail,handles=decode(self.r.stage/'native',self.r.runtime,self.r.profile,self.r.prepared,db)
                bridge.requesters={62023,62024,62026};bridge.check(db,request,uid);db.rollback()
                return dict(status='C_PERMIT_VALID_AT_GATE',native_execution_called=False,rearm_called=False,new_effect=False)
            finally:
                if db.in_transaction:db.rollback()
                for h in handles:h.close()
    def revoke(self):
        grant,g=self.grant()
        with closing(connect(self.r.path)) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                old,allocation,control=self.view(db,grant,g);q.need(old is not None,'C_NOT_ACTIVE')
                if old[0][2]=='REVOKED':db.rollback();return dict(status='C_REVOKED',new_revocation=False)
                q.need(control==g['control'],'REVOCATION_CONTROL_CHANGED')
                db.execute("UPDATE sk_attempts SET state='FENCED' WHERE rid=? AND state='OPEN'",(allocation['rid'],))
                db.execute("UPDATE c_activations SET status='REVOKED' WHERE rid=?",(allocation['rid'],))
                db.execute('UPDATE sk_control SET epoch=epoch+1 WHERE id=1')
                db.execute('INSERT INTO c_activation_events(event,digest) VALUES(?,?)',('C_REVOKED',q.digest(old[1])));db.commit()
                return dict(status='C_REVOKED',new_revocation=True)
            except BaseException:
                if db.in_transaction:db.rollback()
                raise
