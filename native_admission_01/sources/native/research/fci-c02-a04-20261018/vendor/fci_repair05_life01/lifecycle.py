"""Private software lifecycle: persistent cancellation and cause-bound local rearm.
No physical actuator, independent root, or real-time deadline is implemented.
"""
import hashlib
import hmac
import json
import os
from dataclasses import asdict,dataclass,replace
from pathlib import Path
import sqlite3
import sys
from urllib.parse import quote

sys.path.insert(0,str(Path(__file__).resolve().parent/'base05'))
from consumer import (Local as BaseLocal,validate_ticket,effect_step,HOLD,
                      canonical,mac,failures,label_ok,clock_ok,State,rollback,AnchorError)
from base01.authority import repair_claims

STATE_DOMAIN=b'FCI-REPAIR-05-LIFE01/STATE\0'
ENTRY_DOMAIN=b'FCI-REPAIR-05-LIFE01/ENTRY\0'
REARM_DOMAIN=b'FCI-REPAIR-05-LIFE01/REARM\0'
AUDIT_DOMAIN=b'FCI-REPAIR-05-LIFE01/AUDIT\0'
HIST={'DONE':'ACK_EFFECT_HISTORY','CANCELLED':'ACK_CANCEL_HISTORY'}

@dataclass(frozen=True)
class Local:
    instance:str='I'
    target:str='SIM_SINK'
    policy:str='CP'
    context:str='CC'
    mask:int=32
    epoch:int=0
    revision:int=0
    last_time:int=0
    level:int=0
    authority_floor:int=0

    def validate(self):
        if any(not label_ok(x) for x in (self.instance,self.target,self.policy,self.context)):
            raise ValueError('identity/scope')
        if (type(self.mask) is not int or not 0<=self.mask<=127
                or any(not clock_ok(x) for x in (self.epoch,self.revision,self.last_time,self.authority_floor))
                or type(self.level) is not int or not 0<=self.level<=9):raise ValueError('state')

@dataclass(frozen=True)
class Result:
    code:str
    state:Local|None=None
    record:dict|None=None
    new_effect:bool=False

def observed(s,flags,now):
    s.validate();f=failures(flags)
    if not clock_ok(now):raise ValueError('clock')
    m=s.mask|f
    return replace(s,mask=m,epoch=s.epoch+int(m!=s.mask),revision=s.revision+1,last_time=max(s.last_time,now))

def fixture_rearm(s,key,now=100,ttl=10):
    s.validate()
    if not clock_ok(now) or type(ttl) is not int or not 1<=ttl<=60:raise ValueError('time')
    b={'schema':1,'consumer':asdict(s),'action':'REARM_LOCAL','issued_at':now,'expires_at':now+ttl,
       'repairs':repair_claims(s.mask)}
    return {'body':b,'signature':mac(key,REARM_DOMAIN,b)}

def witness_valid(s,w,key,now):
    try:
        if type(w) is not dict or set(w)!={'body','signature'}:return False
        b=w['body']
        if type(b) is not dict or type(b.get('consumer')) is not dict:return False
        Local(**b['consumer']).validate()
        if (type(b) is not dict or set(b)!={'schema','consumer','action','issued_at','expires_at','repairs'}
                or type(b['schema']) is not int or b['schema']!=1 or b['consumer']!=asdict(s)
                or b['action']!='REARM_LOCAL' or not clock_ok(b['issued_at'])
                or type(b['expires_at']) is not int or not 1<=b['expires_at']-b['issued_at']<=60
                or not b['issued_at']<=now<b['expires_at'] or type(w['signature']) is not str
                or not hmac.compare_digest(w['signature'],mac(key,REARM_DOMAIN,b))):return False
        expected=repair_claims(s.mask)
        repairs=b['repairs']
        if type(repairs) is not list or len(repairs)!=len(expected):return False
        for r,e in zip(repairs,expected):
            if (type(r) is not dict or set(r)!={'cause','kind','proof_id'}
                    or r['cause']!=e['cause'] or r['kind']!=e['kind']
                    or type(r['proof_id']) is not str or not r['proof_id']):return False
        return True
    except (KeyError,ValueError,TypeError,OverflowError):return False

def rearm_step(s,flags,now,w,key,authority_revision):
    nxt=observed(s,flags,now)
    if now<s.last_time:return Result('BLOCK_CLOCK',nxt)
    if failures(flags):return Result('BLOCK_REARM_CONDITIONS',nxt)
    if s.mask==0:return Result('BLOCK_NOT_LOCKED',nxt)
    if not witness_valid(s,w,key,now):return Result('BLOCK_REARM_WITNESS',nxt)
    if not clock_ok(authority_revision) or authority_revision<s.authority_floor:return Result('BLOCK_SOURCE',nxt)
    # Never restore the eligibility of old entries. A fresh source accept is needed.
    return Result('REARM_LOCAL_ACCEPTED',replace(nxt,mask=0,epoch=nxt.epoch+1,
                   authority_floor=authority_revision))

def lifecycle_code(status,operation,eligible=True,same=True):
    """Finite primary truth table; fresh effect has separate guard checks."""
    if status not in ('NONE','PENDING','DONE','CANCELLED'):raise ValueError('status')
    if operation not in ('receive','finish','cancel'):raise ValueError('operation')
    if operation!='finish' and status!='NONE' and not same:return 'BLOCK_REQUEST_CONFLICT'
    if status in HIST:return HIST[status]
    if operation=='cancel':return 'CANCELLED'
    if operation=='receive':return 'ACK_DELIVERY' if status=='PENDING' else ('DELIVERED' if eligible else 'DELIVERY_QUARANTINED')
    if status=='NONE':return 'BLOCK_NOT_DELIVERED'
    return 'EFFECT_COMMITTED' if eligible else 'BLOCK_LOCAL_FENCE'

class Consumer:
    def __init__(self,path,key,token_key,receipt_key,rearm_key,instance='I',target='SIM_SINK',_startup=True):
        if any(type(k) is not bytes or len(k)<32 for k in (key,token_key,receipt_key,rearm_key)) or len({key,token_key,receipt_key,rearm_key})!=4:
            raise ValueError('distinct keys')
        self.key,self.token_key,self.receipt_key,self.rearm_key=key,token_key,receipt_key,rearm_key
        self.instance,self.target=instance,target
        try:
            self.db=sqlite3.connect('file:'+quote(str(Path(path).resolve()),safe='/')+'?mode=rw',uri=True,isolation_level=None,timeout=10)
            self.db.execute('PRAGMA synchronous=FULL');self.db.execute('BEGIN IMMEDIATE');s=self._state()
            self.db.execute('SELECT request_id,payload,signature FROM inbox LIMIT 0')
            self.db.execute('SELECT witness_id,payload,signature FROM rearm_audit LIMIT 0')
            # _startup=False is reserved to internal worker attachments of an
            # already commissioned live service in the disposable test fixture.
            if _startup:self._write_state(replace(s,mask=s.mask|32,epoch=s.epoch+1,revision=s.revision+1))
            self.db.execute('COMMIT')
        except (sqlite3.Error,ValueError,TypeError,KeyError):
            if hasattr(self,'db'):self.db.close()
            raise ValueError('consumer unavailable/unauthenticated')

    @classmethod
    def provision(cls,path,key,token_key,receipt_key,rearm_key):
        s=Local();s.validate()
        if any(type(k) is not bytes or len(k)<32 for k in (key,token_key,receipt_key,rearm_key)) or len({key,token_key,receipt_key,rearm_key})!=4:raise ValueError('keys')
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        with sqlite3.connect(path) as d:
            d.execute('PRAGMA synchronous=FULL')
            for table,ident in (('consumer','id INTEGER PRIMARY KEY CHECK(id=1)'),('inbox','request_id TEXT PRIMARY KEY'),('rearm_audit','witness_id TEXT PRIMARY KEY')):
                d.execute('CREATE TABLE '+table+' ('+ident+',payload TEXT NOT NULL,signature TEXT NOT NULL)')
            b=asdict(s);d.execute('INSERT INTO consumer VALUES(1,?,?)',(canonical(b).decode(),mac(key,STATE_DOMAIN,b)))
        return cls(path,key,token_key,receipt_key,rearm_key)

    def _load(self,table,ident,value,domain):
        row=self.db.execute('SELECT payload,signature FROM '+table+' WHERE '+ident+'=?',(value,)).fetchone()
        if row is None:return None
        d=json.loads(row[0])
        if type(row[1]) is not str or not hmac.compare_digest(row[1],mac(self.key,domain,d)):raise ValueError('MAC')
        return d

    def _state(self):
        if self.db.execute('SELECT count(*) FROM consumer').fetchone()[0]!=1:raise ValueError('state count')
        d=self._load('consumer','id',1,STATE_DOMAIN)
        if d is None:raise ValueError('missing state')
        s=Local(**d);s.validate()
        if (s.instance,s.target)!=(self.instance,self.target):raise ValueError('instance/target')
        return s

    def _write_state(self,s):
        s.validate();d=asdict(s)
        self.db.execute('UPDATE consumer SET payload=?,signature=? WHERE id=1',(canonical(d).decode(),mac(self.key,STATE_DOMAIN,d)))

    def _entry(self,rid):
        d=self._load('inbox','request_id',rid,ENTRY_DOMAIN)
        if d is None:return None
        if (type(d) is not dict or set(d)!={'ticket','status','effect','cancel','delivery'}
                or validate_ticket(d['ticket'],self.token_key,self.receipt_key,self.instance,self.target) is None
                or d['ticket']['token']['body']['request_id']!=rid or d['status'] not in ('PENDING','DONE','CANCELLED')):
            raise ValueError('entry shape')
        v=d['delivery']
        if (type(v) is not dict or set(v)!={'epoch','policy','context','eligible'}
                or not clock_ok(v['epoch']) or not label_ok(v['policy']) or not label_ok(v['context'])
                or type(v['eligible']) is not bool):raise ValueError('delivery shape')
        if (d['status']=='PENDING' and (d['effect'] is not None or d['cancel'] is not None)
                or d['status']=='DONE' and (type(d['effect']) is not dict or d['cancel'] is not None)
                or d['status']=='CANCELLED' and (type(d['cancel']) is not dict or d['effect'] is not None)):
            raise ValueError('terminal shape')
        if d['status']=='DONE':
            e=d['effect'];r=d['ticket']['receipt']['body'];t=d['ticket']['token']['body']
            if (set(e)!={'request_id','action','target','accepted_at','effect_time','consumer_revision','ticket_digest'}
                    or any(e[k]!=r[k] for k in ('request_id','action','target','accepted_at'))
                    or not clock_ok(e['consumer_revision']) or not clock_ok(e['effect_time'])
                    or not r['accepted_at']<=e['effect_time']<min(t['expires_at'],r['accepted_at']+HOLD)
                    or e['ticket_digest']!=hashlib.sha256(canonical(d['ticket'])).hexdigest()):raise ValueError('effect')
        if d['status']=='CANCELLED':
            x=d['cancel']
            if (set(x)!={'request_id','cancel_time','epoch','revision','reason','ticket_digest'}
                    or x['request_id']!=rid or x['reason'] not in ('USER_CANCEL','RETIRE_PENDING')
                    or any(not clock_ok(x[k]) for k in ('cancel_time','epoch','revision'))
                    or x['ticket_digest']!=hashlib.sha256(canonical(d['ticket'])).hexdigest()):raise ValueError('cancel')
        return d

    def _write_entry(self,rid,d,new=False):
        if new:self.db.execute('INSERT INTO inbox VALUES(?,?,?)',(rid,canonical(d).decode(),mac(self.key,ENTRY_DOMAIN,d)))
        else:self.db.execute('UPDATE inbox SET payload=?,signature=? WHERE request_id=?',(canonical(d).decode(),mac(self.key,ENTRY_DOMAIN,d),rid))

    def _source(self,anchor,ticket):
        if anchor is None:return False,None
        a=anchor._read();r=ticket['receipt']['body'];before=State(**r['authority_before'])
        if a.instance!=self.instance or anchor.target!=self.target:return False,a
        return anchor._receipt(r['request_id'])==r and a==replace(before,revision=before.revision+1),a

    def _transaction(self,operation,fn,hook=None,anchor=None):
        attempted=False;locked=False
        def point(x):
            if hook:hook(x)
        try:
            point(operation+'_before_tx');self.db.execute('BEGIN IMMEDIATE')
            if anchor is not None:anchor.db.execute('BEGIN IMMEDIATE');locked=True
            r=fn(point)
            point(operation+'_after_write');attempted=True;self.db.execute('COMMIT')
            point(operation+'_after_commit');point(operation+'_before_return');return r
        except (sqlite3.Error,AnchorError,ValueError,TypeError,KeyError,OverflowError,OSError):
            rollback(self.db);return Result('OUTCOME_UNKNOWN' if attempted else 'BLOCK_STORAGE')
        finally:
            if locked:rollback(anchor.db)

    def receive(self,ticket,anchor,now=100,hook=None):
        t=validate_ticket(ticket,self.token_key,self.receipt_key,self.instance,self.target)
        if t is None or not clock_ok(now):return Result('BLOCK_INPUT')
        rid=t['token']['body']['request_id']
        def fn(point):
            s=self._state();old=self._entry(rid)
            if old is not None:return Result(lifecycle_code(old['status'],'receive',same=old['ticket']==t),s,old)
            if now<s.last_time:return Result('BLOCK_CLOCK',s)
            good,a=self._source(anchor,t)
            r=t['receipt']['body'];body=t['token']['body']
            good=bool(good and a.revision>s.authority_floor and s.mask==0 and r['accepted_at']<=now<min(body['expires_at'],r['accepted_at']+HOLD))
            entry={'ticket':t,'status':'PENDING','effect':None,'cancel':None,
                   'delivery':{'epoch':s.epoch,'policy':s.policy,'context':s.context,'eligible':good}}
            self._write_entry(rid,entry,True)
            nxt=replace(s,last_time=max(s.last_time,now),revision=s.revision+1);self._write_state(nxt)
            return Result('DELIVERED' if good else 'DELIVERY_QUARANTINED',nxt,entry)
        return self._transaction('receive',fn,hook,anchor)

    def cancel(self,ticket,now=100,reason='RETIRE_PENDING',hook=None):
        t=validate_ticket(ticket,self.token_key,self.receipt_key,self.instance,self.target)
        if t is None or not clock_ok(now) or reason not in ('USER_CANCEL','RETIRE_PENDING'):return Result('BLOCK_INPUT')
        rid=t['token']['body']['request_id']
        def fn(point):
            s=self._state();old=self._entry(rid)
            code=lifecycle_code(old['status'] if old else 'NONE','cancel',same=old is None or old['ticket']==t)
            if code!='CANCELLED':return Result(code,s,old)
            if now<s.last_time:return Result('BLOCK_CLOCK',s)
            nxt=replace(s,last_time=max(s.last_time,now),revision=s.revision+1)
            entry=old or {'ticket':t,'status':'PENDING','effect':None,'cancel':None,
                         'delivery':{'epoch':s.epoch,'policy':s.policy,'context':s.context,'eligible':False}}
            entry['status']='CANCELLED';entry['cancel']={'request_id':rid,'cancel_time':now,'epoch':nxt.epoch,
                'revision':nxt.revision,'reason':reason,'ticket_digest':hashlib.sha256(canonical(t)).hexdigest()}
            self._write_entry(rid,entry,old is None);self._write_state(nxt)
            return Result(code,nxt,entry)
        return self._transaction('cancel',fn,hook)

    def finish(self,rid,anchor,clock,conditions,hook=None):
        if not label_ok(rid):return Result('BLOCK_INPUT')
        # Terminal queries need no live source; check again under the write lock.
        def fn(point):
            s=self._state();entry=self._entry(rid)
            if entry is None:return Result('BLOCK_NOT_DELIVERED',s)
            if entry['status'] in HIST:return Result(HIST[entry['status']],s,entry)
            times=[];f=0
            for p in ('after_initial_guard','before_final_guard'):
                now=clock();f|=failures(conditions())
                if not clock_ok(now):raise ValueError('clock')
                times.append(now);point(p)
            good,a=self._source(anchor,entry['ticket'])
            now=clock();f|=failures(conditions())
            if not clock_ok(now):raise ValueError('clock')
            times.append(now)
            regressed=any(t<max([s.last_time]+times[:i]) for i,t in enumerate(times))
            flags=tuple(not bool(f&(1<<i)) for i in range(5))
            nxt=observed(s,flags,max(times))
            d=entry['delivery'];fenced=not d['eligible'] or (d['epoch'],d['policy'],d['context'])!=(s.epoch,s.policy,s.context)
            b=BaseLocal(s.instance,s.target,nxt.mask,nxt.last_time,s.level,s.revision)
            base=effect_step(b,(True,)*5,now,'PENDING',entry['ticket'],bool(good and a.revision>s.authority_floor))
            code=base.code
            if regressed:code='BLOCK_CLOCK'
            elif nxt.mask:code='BLOCK_LOCAL_LATCHED'
            elif fenced:code='BLOCK_LOCAL_FENCE'
            point('after_final_guard')
            fresh=code=='EFFECT_COMMITTED'
            if fresh:
                nxt=replace(nxt,level=base.state.level);entry['status']='DONE';entry['effect']=base.effect
                self._write_entry(rid,entry)
            self._write_state(nxt);return Result(code,nxt,entry,fresh)
        # Lock authority only for PENDING, so history remains available during outage.
        try:e=self._entry(rid)
        except (sqlite3.Error,ValueError,TypeError,KeyError):return Result('BLOCK_STORAGE')
        return self._transaction('finish',fn,hook,anchor if e is not None and e['status']=='PENDING' else None)

    def rearm(self,flags,w,anchor,now=100,hook=None):
        try:failures(flags);frozen=json.loads(canonical(w))
        except (ValueError,TypeError,OverflowError):return Result('BLOCK_INPUT')
        if not clock_ok(now):return Result('BLOCK_INPUT')
        wid=hashlib.sha256(canonical(frozen)).hexdigest()
        def fn(point):
            s=self._state();old=self._load('rearm_audit','witness_id',wid,AUDIT_DOMAIN)
            if old is not None:
                if type(old) is not dict or set(old)!={'witness_digest','before','after'} or old['witness_digest']!=wid:raise ValueError('audit')
                Local(**old['before']).validate();Local(**old['after']).validate()
                return Result('ACK_REARM_HISTORY',s,old)
            a=anchor._read() if anchor is not None else None
            source_revision=a.revision if a is not None and a.instance==s.instance and anchor.target==s.target else None
            r=rearm_step(s,flags,now,frozen,self.rearm_key,source_revision)
            self._write_state(r.state)
            if r.code=='REARM_LOCAL_ACCEPTED':
                audit={'witness_digest':wid,'before':asdict(s),'after':asdict(r.state)}
                self.db.execute('INSERT INTO rearm_audit VALUES(?,?,?)',(wid,canonical(audit).decode(),mac(self.key,AUDIT_DOMAIN,audit)))
                return Result(r.code,r.state,audit)
            return r
        return self._transaction('rearm',fn,hook,anchor)

    def history(self):return [self._entry(r[0]) for r in self.db.execute('SELECT request_id FROM inbox ORDER BY request_id')]
    def set_scope(self,policy,context,anchor,now=100,hook=None):
        if not label_ok(policy) or not label_ok(context) or not clock_ok(now):return Result('BLOCK_INPUT')
        def fn(point):
            s=self._state()
            if now<s.last_time:return Result('BLOCK_CLOCK',s)
            if (policy,context)==(s.policy,s.context):return Result('SCOPE_UNCHANGED',s)
            if anchor is None:return Result('BLOCK_SOURCE',s)
            a=anchor._read()
            if a.instance!=s.instance or anchor.target!=s.target:return Result('BLOCK_SOURCE',s)
            if a.revision<s.authority_floor:return Result('BLOCK_SOURCE',s)
            nxt=replace(s,policy=policy,context=context,mask=s.mask|64,epoch=s.epoch+1,
                        revision=s.revision+1,last_time=now,authority_floor=a.revision)
            self._write_state(nxt);return Result('LOCAL_SCOPE_RECORDED',nxt)
        return self._transaction('scope',fn,hook,anchor)
    def close(self):self.db.close()
