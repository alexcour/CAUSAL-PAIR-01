"""Private scoped digital REF prototype. The sink is a SQLite log, not hardware.

Guard + authority update + one accepted-command row share an anchor transaction.
Physical execution, independent storage and NoBypass are external obligations.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import sys

# Frozen REPAIR-03 retains its original imports and byte identity.
sys.path.insert(0, str(Path(__file__).resolve().parent/'base03'))
from anchored import (AnchoredAuthority, SQLiteAnchor, AnchorError, FreshnessError,
                      rollback)
from base01.authority import (State, StorageError, canonical, mac, observe_step,
                              failures)

TOKEN_DOMAIN = b'FCI-REPAIR-04/TOKEN\0'
RECEIPT_DOMAIN = b'FCI-REPAIR-04/RECEIPT\0'
MAX_TTL = 15


def command_ok(action):
    return (type(action) is dict and set(action) == {'op','value'}
            and action['op'] == 'set_level' and type(action['value']) is int
            and 0 <= action['value'] <= 9)


def label_ok(label):
    return type(label) is str and 0 < len(label) <= 64


def clock_ok(now):
    return type(now) is int and now >= 0


def token_for(state, action, target, request_id, key, now, ttl=10):
    """Trusted test issuer, not a semantic industrial certification service."""
    state.validate()
    if (state.mask != 0 or not command_ok(action) or not label_ok(target)
            or not label_ok(request_id) or not clock_ok(now)
            or type(ttl) is not int or not 1 <= ttl <= MAX_TTL):
        raise ValueError('invalid nominal token request')
    body = {'schema':1, 'authority':asdict(state), 'action':dict(action),
            'target':target, 'request_id':request_id,
            'issued_at':now, 'expires_at':now+ttl}
    return {'body':body, 'signature':mac(key,TOKEN_DOMAIN,body)}


def parse_token(token, key, instance):
    try:
        if type(token) is not dict or set(token) != {'body','signature'}:
            return None
        b,sig = token['body'],token['signature']
        if (type(b) is not dict or set(b) != {'schema','authority','action','target',
                'request_id','issued_at','expires_at'} or type(sig) is not str
                or type(b['schema']) is not int or b['schema'] != 1
                or type(b['authority']) is not dict):
            return None
        # Own the authenticated body; later caller mutations cannot change the
        # command recorded after the guard.
        b=json.loads(canonical(b))
        state=State(**b['authority']); state.validate()
        if (state.instance != instance or state.mask != 0 or not command_ok(b['action'])
                or not label_ok(b['target']) or not label_ok(b['request_id'])
                or not clock_ok(b['issued_at']) or type(b['expires_at']) is not int
                or not 1 <= b['expires_at']-b['issued_at'] <= MAX_TTL
                or not hmac.compare_digest(sig,mac(key,TOKEN_DOMAIN,b))):
            return None
        return b
    except (ValueError, TypeError, KeyError, OverflowError):
        return None


def receipt_body(state, body, now):
    return {'schema':1,'instance':state.instance,'request_id':body['request_id'],
            'action':body['action'],'target':body['target'],
            'policy':state.policy,'context':state.context,
            'authority_before':asdict(state),'accepted_at':now,
            'token_digest':hashlib.sha256(canonical(body)).hexdigest()}


@dataclass(frozen=True)
class ConsumeResult:
    code: str
    state: State | None
    receipt: dict | None = None
    new_record: bool = False


@dataclass(frozen=True)
class IssueResult:
    code: str
    state: State | None
    token: dict | None = None


def consume_step(state, flags, token, action, target, now, token_key, previous=None):
    """Pure transition; previous must be a trusted validated receipt body.

    An ACK is historical evidence, including for an expired token, never a new
    command. Current observations are still accumulated on every formed call.
    """
    if not clock_ok(now) or not command_ok(action) or not label_ok(target):
        raise ValueError('malformed consumption arguments')
    observed=observe_step(state,flags).state
    b=parse_token(token,token_key,state.instance)
    if b is None:
        return ConsumeResult('BLOCK_TOKEN',observed)
    if b['action'] != action:
        return ConsumeResult('BLOCK_ACTION',observed)
    if b['target'] != target:
        return ConsumeResult('BLOCK_TARGET',observed)
    if previous is not None:
        intent=(state.instance,b['request_id'],action,target,
                b['authority']['policy'],b['authority']['context'])
        old=(previous['instance'],previous['request_id'],previous['action'],previous['target'],
             previous['policy'],previous['context'])
        if intent != old:
            return ConsumeResult('BLOCK_REQUEST_CONFLICT',observed)
        if now < previous['accepted_at']:
            return ConsumeResult('BLOCK_CLOCK',observed)
        return ConsumeResult('ACK_PREVIOUS',observed,previous,False)
    if observed.mask != 0:
        return ConsumeResult('BLOCK_LATCHED',observed)
    if b['authority'] != asdict(state):
        return ConsumeResult('BLOCK_STALE_TOKEN',observed)
    if not b['issued_at'] <= now < b['expires_at']:
        return ConsumeResult('BLOCK_TIME',observed)
    return ConsumeResult('DISPATCH_RECORDED',observed,receipt_body(state,b,now),True)


class PossibleCommitError(AnchorError):
    """Commit response failed; caller must not infer absence of submission."""
    pass


class SQLiteSinkAnchor(SQLiteAnchor):
    """Authority and simulated accepted-command log in the same trust domain.

    A local database is only a fixture. Stable request IDs never expire/purge.
    No physical completion can be inferred from a receipt.
    """
    def __init__(self,path,key,instance,token_key,receipt_key,target='SIM_SINK'):
        if (any(type(k) is not bytes or len(k)<32 for k in (key,token_key,receipt_key))
                or len({key,token_key,receipt_key})!=3 or not label_ok(target)):
            raise ValueError('distinct keys and target required')
        self.token_key,self.receipt_key,self.target=token_key,receipt_key,target
        super().__init__(path,key,instance)
        try:
            self.db.execute('SELECT request_id,payload,signature FROM receipts LIMIT 0')
        except sqlite3.Error as exc:
            self.close()
            raise AnchorError('receipt schema unavailable') from exc

    @classmethod
    def provision(cls,path,key,initial,token_key,receipt_key,target='SIM_SINK'):
        if (any(type(k) is not bytes or len(k)<32 for k in (key,token_key,receipt_key))
                or len({key,token_key,receipt_key})!=3 or not label_ok(target)):
            raise ValueError('distinct keys and target required')
        base=SQLiteAnchor.provision(path,key,initial)
        try:
            base.db.execute('CREATE TABLE receipts (request_id TEXT PRIMARY KEY, payload TEXT NOT NULL, signature TEXT NOT NULL)')
        finally:
            base.close()
        return cls(path,key,initial.instance,token_key,receipt_key,target)

    def _receipt(self,request_id):
        row=self.db.execute('SELECT payload,signature FROM receipts WHERE request_id=?',(request_id,)).fetchone()
        if row is None:
            return None
        data,sig=json.loads(row[0]),row[1]
        if (type(data) is not dict or set(data)!= {'schema','instance','request_id','action','target',
                'policy','context','authority_before','accepted_at','token_digest'}
                or type(data['schema']) is not int or data['schema']!=1
                or data['instance']!=self.instance or data['request_id']!=request_id
                or not label_ok(request_id) or not command_ok(data['action'])
                or not label_ok(data['target']) or not clock_ok(data['accepted_at'])
                or type(data['token_digest']) is not str or len(data['token_digest'])!=64
                or any(c not in '0123456789abcdef' for c in data['token_digest'])
                or type(sig) is not str
                or not hmac.compare_digest(sig,mac(self.receipt_key,RECEIPT_DOMAIN,data))):
            raise ValueError('invalid receipt')
        s=State(**data['authority_before']); s.validate()
        if (s.mask!=0 or s.instance!=self.instance or (s.policy,s.context)!=(data['policy'],data['context'])):
            raise ValueError('receipt authority mismatch')
        return data

    def records(self):
        try:
            ids=[r[0] for r in self.db.execute('SELECT request_id FROM receipts ORDER BY request_id')]
            return [self._seal(self._receipt(r)) for r in ids]
        except (sqlite3.Error,ValueError,TypeError,KeyError) as exc:
            raise AnchorError('receipt read failed') from exc

    def _seal(self,data):
        return {'body':data,'signature':mac(self.receipt_key,RECEIPT_DOMAIN,data)}

    def record(self,expected,flags,token,action,now,hook=None):
        commit_attempted=False
        def point(label):
            if hook is not None: hook(label)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            state=self._read()
            if state!=expected:
                raise FreshnessError('replica not current')
            b=parse_token(token,self.token_key,self.instance)
            previous=self._receipt(b['request_id']) if b is not None else None
            result=consume_step(state,flags,token,action,self.target,now,self.token_key,previous)
            point('after_guard')
            data=asdict(result.state)
            self.db.execute('UPDATE anchor SET payload=?,signature=? WHERE id=1',(
                canonical(data).decode(),mac(self.key,b'FCI-REPAIR-03/ANCHOR\0',data)))
            if result.new_record:
                envelope=self._seal(result.receipt)
                self.db.execute('INSERT INTO receipts VALUES(?,?,?)',(
                    result.receipt['request_id'],canonical(result.receipt).decode(),envelope['signature']))
            point('after_anchor_write')
            commit_attempted=True
            self.db.execute('COMMIT')
            return replace(result,receipt=self._seal(result.receipt) if result.receipt is not None else None)
        except FreshnessError:
            rollback(self.db)
            raise
        except (sqlite3.Error,ValueError,TypeError,KeyError,OverflowError,OSError) as exc:
            rollback(self.db)
            if commit_attempted:
                raise PossibleCommitError('anchor commit outcome not certified') from exc
            raise AnchorError('anchor/simulated sink transaction failed') from exc


class DispatchAuthority(AnchoredAuthority):
    def _attach(self,path,state_key,rearm_key,instance,anchor,hook):
        if len({state_key,rearm_key,anchor.key,anchor.token_key,anchor.receipt_key})!=5:
            raise ValueError('five distinct keys required')
        super()._attach(path,state_key,rearm_key,instance,anchor,hook)

    def issue(self,flags,action,request_id,now,ttl=10):
        failures(flags)
        if (not command_ok(action) or not label_ok(request_id) or not clock_ok(now)
                or type(ttl) is not int or not 1<=ttl<=MAX_TTL):
            return IssueResult('BLOCK_INPUT',None)
        decision=self.observe(flags)
        if not decision.nominal_allowed:
            return IssueResult(decision.code,decision.state)
        token=token_for(decision.state,action,self.anchor.target,request_id,
                        self.anchor.token_key,now,ttl)
        return IssueResult('TOKEN_ISSUED',decision.state,token)

    def consume(self,flags,token,action,now):
        failures(flags)
        if not command_ok(action) or not clock_ok(now):
            return ConsumeResult('BLOCK_INPUT',None)
        try:
            action=json.loads(canonical(action))
            token=json.loads(canonical(token))
        except (TypeError,ValueError,OverflowError):
            return ConsumeResult('BLOCK_INPUT',None)
        committed=False
        try:
            self.db.execute('BEGIN IMMEDIATE')
            local=self._read()
            self._point('before_anchor_tx')
            result=self.anchor.record(local,flags,token,action,now,self.hook)
            committed=True
            self._point('after_anchor_commit')
            self._write(result.state)
            self._point('after_replica_write')
            self.db.execute('COMMIT')
            self._point('after_replica_commit')
            self._point('before_return')
            return result
        except PossibleCommitError:
            rollback(self.db)
            return ConsumeResult('OUTCOME_UNKNOWN',None)
        except FreshnessError:
            rollback(self.db)
            return ConsumeResult('OUTCOME_UNKNOWN' if committed else 'BLOCK_FRESHNESS',None)
        except AnchorError:
            rollback(self.db)
            return ConsumeResult('OUTCOME_UNKNOWN' if committed else 'BLOCK_ANCHOR',None)
        except (sqlite3.Error,ValueError,TypeError,KeyError,OverflowError,OSError):
            rollback(self.db)
            return ConsumeResult('OUTCOME_UNKNOWN' if committed else 'BLOCK_STORAGE',None)
