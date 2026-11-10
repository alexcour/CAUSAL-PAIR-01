"""Instrumented software consumer. A simulated effect is a SQLite level update.
No physical actuator, hardware clock deadline or independent root is implemented.
"""
from dataclasses import asdict, dataclass, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import sys
from urllib.parse import quote

sys.path.insert(0,str(Path(__file__).resolve().parent/'base04'))
from dispatch import (State, canonical, mac, failures, parse_token, command_ok,
                      label_ok, clock_ok, RECEIPT_DOMAIN, AnchorError, rollback)

HOLD=3
STATE_DOMAIN=b'FCI-REPAIR-05/CONSUMER\0'
ENTRY_DOMAIN=b'FCI-REPAIR-05/ENTRY\0'


@dataclass(frozen=True)
class Local:
    instance:str
    target:str
    mask:int=0
    last_time:int=0
    level:int=0
    revision:int=0

    def validate(self):
        if (not label_ok(self.instance) or not label_ok(self.target)
                or type(self.mask) is not int or not 0<=self.mask<=127
                or not clock_ok(self.last_time) or not clock_ok(self.revision)
                or type(self.level) is not int or not 0<=self.level<=9):
            raise ValueError('invalid consumer state')


@dataclass(frozen=True)
class Result:
    code:str
    state:Local|None=None
    effect:dict|None=None
    new_effect:bool=False


def validate_ticket(ticket,token_key,receipt_key,instance,target):
    """Validate original token plus the authenticated accepted receipt."""
    try:
        ticket=json.loads(canonical(ticket))
        if type(ticket) is not dict or set(ticket)!={'token','receipt'}:return None
        t=parse_token(ticket['token'],token_key,instance)
        e=ticket['receipt']
        if t is None or type(e) is not dict or set(e)!={'body','signature'}:return None
        r=e['body']
        fields={'schema','instance','request_id','action','target','policy','context',
                'authority_before','accepted_at','token_digest'}
        if (type(r) is not dict or set(r)!=fields or type(e['signature']) is not str
                or type(r['schema']) is not int or r['schema']!=1
                or not hmac.compare_digest(e['signature'],mac(receipt_key,RECEIPT_DOMAIN,r))
                or r['instance']!=instance or r['target']!=target or t['target']!=target
                or r['authority_before']!=t['authority'] or r['action']!=t['action']
                or r['request_id']!=t['request_id']
                or (r['policy'],r['context'])!=(t['authority']['policy'],t['authority']['context'])
                or not clock_ok(r['accepted_at'])
                or not t['issued_at']<=r['accepted_at']<t['expires_at']
                or r['token_digest']!=hashlib.sha256(canonical(t)).hexdigest()):return None
        return ticket
    except (ValueError,TypeError,KeyError,OverflowError):return None


def effect_step(s,flags,now,status,ticket,source_ok):
    """Pure scoped transition. DONE is a query, not an observation or permission."""
    s.validate()
    if status=='DONE':return Result('ACK_EFFECT_HISTORY',s)
    if status=='NONE':return Result('BLOCK_NOT_DELIVERED',s)
    if status!='PENDING':raise ValueError('invalid status')
    f=failures(flags)
    if not clock_ok(now):raise ValueError('invalid clock')
    nxt=replace(s,mask=s.mask|f,last_time=max(s.last_time,now),revision=s.revision+1)
    if now<s.last_time:return Result('BLOCK_CLOCK',nxt)
    if nxt.mask:return Result('BLOCK_LOCAL_LATCHED',nxt)
    if not source_ok:return Result('BLOCK_SOURCE',nxt)
    t,r=ticket['token']['body'],ticket['receipt']['body']
    if not r['accepted_at']<=now<min(t['expires_at'],r['accepted_at']+HOLD):
        return Result('BLOCK_DEADLINE',nxt)
    effect={'request_id':r['request_id'],'action':r['action'],'target':r['target'],
            'accepted_at':r['accepted_at'],'effect_time':now,'consumer_revision':nxt.revision,
            'ticket_digest':hashlib.sha256(canonical(ticket)).hexdigest()}
    return Result('EFFECT_COMMITTED',replace(nxt,level=r['action']['value']),effect,True)


class Consumer:
    def __init__(self,path,key,token_key,receipt_key,instance='I',target='SIM_SINK'):
        if (any(type(k) is not bytes or len(k)<32 for k in (key,token_key,receipt_key))
                or len({key,token_key,receipt_key})!=3):raise ValueError('distinct fixture keys required')
        self.key,self.token_key,self.receipt_key=key,token_key,receipt_key
        self.instance,self.target=instance,target
        try:
            self.db=sqlite3.connect('file:'+quote(str(Path(path).resolve()),safe='/')+'?mode=rw',uri=True,
                                   isolation_level=None,timeout=10)
            self.db.execute('PRAGMA synchronous=FULL')
            self._state()
            self.db.execute('SELECT request_id,payload,signature FROM inbox LIMIT 0')
        except (sqlite3.Error,ValueError,TypeError,KeyError):
            if hasattr(self,'db'):self.db.close()
            raise ValueError('consumer unavailable or unauthenticated')

    @classmethod
    def provision(cls,path,key,token_key,receipt_key,instance='I',target='SIM_SINK'):
        s=Local(instance,target);s.validate()
        if any(type(k) is not bytes or len(k)<32 for k in (key,token_key,receipt_key)) or len({key,token_key,receipt_key})!=3:raise ValueError('keys')
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        with sqlite3.connect(path) as d:
            d.execute('PRAGMA synchronous=FULL')
            d.execute('CREATE TABLE consumer (id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT,signature TEXT)')
            d.execute('CREATE TABLE inbox (request_id TEXT PRIMARY KEY,payload TEXT,signature TEXT)')
            data=asdict(s);d.execute('INSERT INTO consumer VALUES(1,?,?)',(canonical(data).decode(),mac(key,STATE_DOMAIN,data)))
        return cls(path,key,token_key,receipt_key,instance,target)

    def _state(self):
        rows=self.db.execute('SELECT payload,signature FROM consumer').fetchall()
        if len(rows)!=1:raise ValueError('one consumer state required')
        d=json.loads(rows[0][0]);sig=rows[0][1]
        if not hmac.compare_digest(sig,mac(self.key,STATE_DOMAIN,d)):raise ValueError('state MAC')
        s=Local(**d);s.validate()
        if (s.instance,s.target)!=(self.instance,self.target):raise ValueError('wrong consumer')
        return s

    def _write_state(self,s):
        s.validate();d=asdict(s)
        self.db.execute('UPDATE consumer SET payload=?,signature=? WHERE id=1',(canonical(d).decode(),mac(self.key,STATE_DOMAIN,d)))

    def _entry(self,rid):
        row=self.db.execute('SELECT payload,signature FROM inbox WHERE request_id=?',(rid,)).fetchone()
        if row is None:return None
        d=json.loads(row[0])
        if (type(d) is not dict or set(d)!={'ticket','status','effect'}
                or not hmac.compare_digest(row[1],mac(self.key,ENTRY_DOMAIN,d))
                or validate_ticket(d['ticket'],self.token_key,self.receipt_key,self.instance,self.target) is None
                or d['ticket']['token']['body']['request_id']!=rid
                or d['status'] not in ('PENDING','DONE')):raise ValueError('invalid entry')
        if d['status']=='PENDING':
            if d['effect'] is not None:raise ValueError('pending effect')
        else:
            e=d['effect'];r=d['ticket']['receipt']['body'];t=d['ticket']['token']['body']
            if (type(e) is not dict or set(e)!={'request_id','action','target','accepted_at','effect_time','consumer_revision','ticket_digest'}
                    or any(e[k]!=r[k] for k in ('request_id','action','target','accepted_at'))
                    or not clock_ok(e['effect_time']) or not clock_ok(e['consumer_revision'])
                    or not r['accepted_at']<=e['effect_time']<min(t['expires_at'],r['accepted_at']+HOLD)
                    or e['ticket_digest']!=hashlib.sha256(canonical(d['ticket'])).hexdigest()):raise ValueError('invalid effect')
        return d

    def _write_entry(self,rid,d,new=False):
        data,sig=canonical(d).decode(),mac(self.key,ENTRY_DOMAIN,d)
        if new:self.db.execute('INSERT INTO inbox VALUES(?,?,?)',(rid,data,sig))
        else:self.db.execute('UPDATE inbox SET payload=?,signature=? WHERE request_id=?',(data,sig,rid))

    def receive(self,ticket,hook=None):
        t=validate_ticket(ticket,self.token_key,self.receipt_key,self.instance,self.target)
        if t is None:return Result('BLOCK_TICKET')
        rid=t['token']['body']['request_id'];attempted=False
        def point(x):
            if hook:hook(x)
        try:
            point('receive_before_tx');self.db.execute('BEGIN IMMEDIATE');s=self._state();old=self._entry(rid)
            if old is not None:
                code=('ACK_EFFECT_HISTORY' if old['status']=='DONE' else 'ACK_DELIVERY') if old['ticket']==t else 'BLOCK_REQUEST_CONFLICT'
                result=Result(code,s,old['effect'] if code=='ACK_EFFECT_HISTORY' else None)
            else:
                self._write_entry(rid,{'ticket':t,'status':'PENDING','effect':None},True);result=Result('DELIVERED',s)
            point('receive_after_write');attempted=True;self.db.execute('COMMIT');point('receive_after_commit');point('receive_before_return')
            return result
        except (sqlite3.Error,ValueError,TypeError,KeyError,OverflowError,OSError):
            rollback(self.db);return Result('OUTCOME_UNKNOWN' if attempted else 'BLOCK_STORAGE')

    def finish(self,rid,anchor,clock,conditions,hook=None):
        """Provider callbacks are trusted. Last recheck precedes simulated mutation.
        Holding the anchor lock serializes cooperative authority writers only.
        """
        if not label_ok(rid):return Result('BLOCK_INPUT')
        attempted=False;anchor_locked=False
        def point(x):
            if hook:hook(x)
        try:
            point('finish_before_tx');self.db.execute('BEGIN IMMEDIATE');s=self._state();entry=self._entry(rid)
            if entry is None:result=Result('BLOCK_NOT_DELIVERED',s)
            elif entry['status']=='DONE':result=Result('ACK_EFFECT_HISTORY',s,entry['effect'])
            else:
                # Observe once, then observe again after the initial-to-final gap.
                first=clock();f1=failures(conditions())
                if not clock_ok(first):raise ValueError('clock provider')
                clock_regressed=first<s.last_time
                point('after_initial_guard')
                second=clock();f2=failures(conditions())
                if not clock_ok(second):raise ValueError('clock provider')
                clock_regressed=clock_regressed or second<max(s.last_time,first)
                flags=tuple(not bool((f1|f2)&(1<<i)) for i in range(5))
                # Preserve first reading in the high-watermark: no intra-call regression.
                s=replace(s,last_time=max(s.last_time,first))
                source_ok=False
                if anchor is not None:
                    anchor.db.execute('BEGIN IMMEDIATE');anchor_locked=True
                    auth=anchor._read();receipt=anchor._receipt(rid)
                    r=entry['ticket']['receipt']['body'];before=State(**r['authority_before'])
                    source_ok=(receipt==r and auth==replace(before,revision=before.revision+1))
                point('before_final_guard')
                # Locks may wait. Clock/conditions must be reread AFTER lock acquisition.
                final=clock();f3=failures(conditions())
                flags=tuple(flags[i] and not bool(f3&(1<<i)) for i in range(5))
                s=replace(s,last_time=max(s.last_time,second))
                result=effect_step(s,flags,final,'PENDING',entry['ticket'],source_ok)
                if clock_regressed:
                    result=Result('BLOCK_CLOCK',replace(result.state,level=s.level),None,False)
                point('after_final_guard')
                self._write_state(result.state)
                if result.new_effect:
                    entry['status']='DONE';entry['effect']=result.effect;self._write_entry(rid,entry)
            point('finish_after_write');attempted=True;self.db.execute('COMMIT');point('finish_after_commit');point('finish_before_return')
            return result
        except (sqlite3.Error,AnchorError,ValueError,TypeError,KeyError,OverflowError,OSError):
            rollback(self.db);return Result('OUTCOME_UNKNOWN' if attempted else 'BLOCK_STORAGE')
        finally:
            if anchor_locked:rollback(anchor.db)

    def history(self):
        return [self._entry(r[0]) for r in self.db.execute('SELECT request_id FROM inbox ORDER BY request_id')]

    def close(self):self.db.close()
