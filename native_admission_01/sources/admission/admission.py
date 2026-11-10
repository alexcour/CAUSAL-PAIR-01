"""One-use C admission in retained native SQL. No native permit or execution.

Trusted root/OS/single service owner and no live clones remain assumptions.
ADMISSION_ONLY is deliberately not OPEN: frozen issue() must refuse it.
"""
import copy,hashlib,json,sqlite3,uuid
from contextlib import closing
from pathlib import Path
import quiescence as q
from retirement import Retirement,connect
GRANT=b'FCI-NATIVE-C-ADMISSION-GRANT/1\0'
RECEIPT=b'FCI-NATIVE-C-ADMISSION/1\0'
RPC=b'FCI-NATIVE-C-ADMISSION-RPC/1\0'
C_UID=62026

def provision(path):
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE native_admissions(retirement_id TEXT PRIMARY KEY,grant_id TEXT UNIQUE NOT NULL,envelope TEXT NOT NULL)')
        db.execute('CREATE TABLE native_admission_events(seq INTEGER PRIMARY KEY,event TEXT NOT NULL,grant_id TEXT NOT NULL,receipt_digest TEXT NOT NULL)')

def policy():return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

def project(stores,profile,allocation):
    s=copy.deepcopy(stores);main=s[q.authority_names(profile)[0]]
    for table in ('native_admissions','native_admission_events'):
        q.need(len(main[table]['rows'])==1,'ONE_ADMISSION_RECORD');main[table]['rows']=[]
    t=main['sk_attempts'];idx=t['columns'].index('rid');matched=[r for r in t['rows'] if r[idx]==allocation['rid']]
    q.need(len(matched)==1 and dict(zip(t['columns'],matched[0]))==dict(k=q.canonical(allocation['key']).decode(),g=3,
        attempt_id=allocation['attempt_id'],uid=C_UID,rid=allocation['rid'],state='ADMISSION_ONLY'),'C_ADMISSION_ROW')
    t['rows'].remove(matched[0]);return s

class Admission:
    def __init__(self,retirement,grant_path):
        self.r=retirement;self.grant_path=Path(grant_path)
    def grant(self):
        p=self.grant_path
        for f in (p,p.parent):
            s=f.lstat();q.need(s.st_uid==0 and not s.st_mode&0o022 and not f.is_symlink(),'ROOT_GRANT_BOUNDARY')
        env=json.loads(p.read_text());b=q.verify(env,self.r.context['supervisor_public'],GRANT)
        expected={'schema','grant_id','scope','retirement_digest','state_digest','authority_inventory','successor_uid','generation',
            'admission_policy_sha256','retirement_owner_wait','no_live_clones_assumed','execution_authorized','recovery_authorized'}
        q.need(set(b)==expected and b['schema']=='FCI-NATIVE-C-ADMISSION-GRANT/1' and b['scope']==self.r.context['scope']
            and type(b['successor_uid']) is int and b['successor_uid']==C_UID and type(b['generation']) is int and b['generation']==3
            and b['admission_policy_sha256']==policy() and b['no_live_clones_assumed'] is True
            and b['execution_authorized'] is b['recovery_authorized'] is False
            and type(b['grant_id']) is str and len(b['grant_id'])==32,'EXACT_ADMISSION_GRANT')
        w=b['retirement_owner_wait'];q.need(set(w)=={'pid','exit','waited'} and type(w['pid']) is int and w['pid']>0
            and type(w['exit']) is int and w['exit']==-15 and w['waited'] is True,'PREVIOUS_CLOSURE_OWNER_WAITED')
        return env,b
    def inventory(self,grant,after=False):
        current=q.inventory(self.r.runtime,self.r.profile);original=grant['authority_inventory'];main=q.authority_names(self.r.profile)[0]
        q.need(set(current)==set(original)==set(q.authority_names(self.r.profile)),'COMPLETE_FRESH_AUTHORITY')
        for name,entry in current.items():
            q.need({k:v for k,v in entry.items() if k!='sha256'}=={k:v for k,v in original[name].items() if k!='sha256'}
                and ((after and name==main) or entry['sha256']==original[name]['sha256']),'FRESH_AUTHORITY_BINDING')
    def admit(self,abort=False):
        grant,g=self.grant();r=self.r
        with closing(connect(r.path)) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                stored=db.execute('SELECT envelope FROM native_admissions WHERE grant_id=?',(g['grant_id'],)).fetchone()
                self.inventory(g,after=stored is not None);stores=r.stores()
                if stored:
                    env=json.loads(stored[0]);b=q.verify(env,r.context['sink_public'],RECEIPT)
                    q.need(b['schema']=='FCI-NATIVE-C-ADMISSION/1' and b['grant_digest']==q.digest(grant)
                        and b['admission_policy_sha256']==policy() and b['execution_authorized'] is b['recovery_authorized'] is False,'STORED_ADMISSION_BINDING')
                    self.inventory(g,after=True);q.need(q.digest(project(stores,r.profile,b['allocation']))==g['state_digest'],'ONLY_DECLARED_ADMISSION_DELTA')
                    db.rollback();return dict(status='ADMISSION_RETRIEVED',new_allocation=False,receipt=env)
                self.inventory(g);q.need(q.digest(stores)==g['state_digest'],'FRESH_STATE_DIGEST')
                cert=r.stored(db);q.need(cert is not None,'RETIRED_B_REQUIRED');ret=r.verify_stored(cert,stores)
                q.need(q.digest(cert)==g['retirement_digest'],'GRANT_RETIRED_B_BINDING')
                p=r.prepared['request_B']['permit']['body'];kt=q.canonical(p['key']).decode()
                current=db.execute('SELECT g,attempt_id,uid,rid,state FROM sk_attempts WHERE k=? ORDER BY g DESC LIMIT 1',(kt,)).fetchone()
                q.need(current==(2,p['attempt_id'],62024,r.rid,'FENCED'),'RETIRED_B_IS_CURRENT')
                control=db.execute('SELECT policy,epoch,revoked FROM sk_control WHERE id=1').fetchone()
                q.need(control[0]==p['policy'] and not control[2],'CURRENT_POLICY_NOT_REVOKED')
                business=db.execute('SELECT h,result FROM sk_business WHERE k=?',(kt,)).fetchone()
                q.need(business==(p['content_hash'],None),'NO_BUSINESS_RESULT')
                q.need(db.execute('SELECT count(*) FROM '+('demo_effects' if r.profile=='FCI' else 'effects')).fetchone()[0]==0,'NO_NATIVE_EFFECT')
                attempt=uuid.uuid4().hex
                rid=hashlib.sha256(b'SAME-K-NATIVE-ATTEMPT/1\0'+q.canonical([p['key'],p['content_hash'],3,attempt,C_UID])).hexdigest()
                allocation=dict(key=p['key'],h=p['content_hash'],generation=3,attempt_id=attempt,uid=C_UID,rid=rid)
                b=dict(schema='FCI-NATIVE-C-ADMISSION/1',grant_digest=q.digest(grant),retirement_digest=q.digest(cert),
                    retirement_id=ret['retirement_id'],allocation=allocation,admission_policy_sha256=policy(),
                    state='ADMISSION_ONLY',execution_authorized=False,recovery_authorized=False,native_permit_issued=False)
                env=q.signed(r.sink,RECEIPT,b)
                db.execute("INSERT INTO sk_attempts VALUES(?,?,?,?,?,'ADMISSION_ONLY')",(kt,3,attempt,C_UID,rid))
                db.execute('INSERT INTO native_admissions VALUES(?,?,?)',(ret['retirement_id'],g['grant_id'],q.canonical(env).decode()))
                db.execute('INSERT INTO native_admission_events(event,grant_id,receipt_digest) VALUES(?,?,?)',('C_ADMITTED_ONLY',g['grant_id'],q.digest(env)))
                q.need(db.in_transaction,'REAL_ADMISSION_TRANSACTION')
                if abort:raise RuntimeError('INJECTED_ADMISSION_BEFORE_COMMIT')
                db.commit();q.need(q.digest(project(r.stores(),r.profile,allocation))==g['state_digest'],'EXACT_COMMITTED_ADMISSION_DELTA')
                return dict(status='C_ADMITTED_ONLY',new_allocation=True,receipt=env)
            except BaseException:
                if db.in_transaction:db.rollback()
                raise

    def probe_issue(self):
        r=self.r;before=r.stores();_,g=self.grant()
        with closing(connect(r.path)) as db:
            row=db.execute('SELECT envelope FROM native_admissions WHERE grant_id=?',(g['grant_id'],)).fetchone();q.need(row is not None,'C_NOT_ADMITTED')
            b=q.verify(json.loads(row[0]),r.context['sink_public'],RECEIPT)
            from retirement import decode
            native,bridge,detail,handles=decode(r.stage/'native',r.runtime,r.profile,r.prepared,db)
            try:
                try:bridge.issue(b['allocation'],62022);raise RuntimeError('ADMISSION_ISSUED_NATIVE_PERMIT')
                except bridge.auth.AuthorizationRefused as exc:
                    q.need(str(exc)=='STALE_ALLOCATION','EXACT_FROZEN_ISSUE_REFUSAL')
                    result=dict(code=str(exc),native_permit_issued=False,normal_service_constructor_called=False,rearm_called=False)
                q.need(r.stores()==before,'NO_ISSUE_PROBE_WRITES');return result
            finally:
                for h in handles:h.close()
