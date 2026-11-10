"""RC3 late sampled revalidation of staged SQLite effects, not atomic actuation.

The independent attempt reservation has already committed when this runs.
Only uncommitted simulated writes can be withdrawn. A change after the last
sample remains C004; checked_at is a sample time, never a measured commit time.
"""
import copy
from dataclasses import replace
import hashlib
import hmac

from .guarded_consumer import GuardedConsumer
from .spend_ledger import ticket_digest
from .strict_json import canonical, loads, shape, integer
from lifecycle import Result, failures, clock_ok, HOLD

DOMAIN = b'FCI-C004-SAMPLED-FENCE/1\0'
DENIALS = ('BLOCK_COMMIT_CLOCK', 'BLOCK_COMMIT_CONDITIONS', 'BLOCK_COMMIT_SOURCE',
           'BLOCK_COMMIT_DEADLINE', 'BLOCK_COMMIT_SCOPE')


class FinalizingConsumer(GuardedConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            self.db.execute('SELECT request_id,payload,signature FROM commit_fence LIMIT 0')
        except Exception:
            self.close()
            raise ValueError('commit fence journal missing; no automatic migration')

    @staticmethod
    def provision_journal(db):
        # Offline fresh-fixture setup only. Never called during service opening.
        db.execute('CREATE TABLE commit_fence(request_id TEXT PRIMARY KEY, payload BLOB NOT NULL, signature TEXT NOT NULL)')

    def _fence(self, rid):
        row = self.db.execute('SELECT payload,signature FROM commit_fence WHERE request_id=?', (rid,)).fetchone()
        if row is None:
            return None
        data, signature = row
        if type(data) is not bytes or type(signature) is not str:
            raise ValueError('commit fence encoding')
        if not hmac.compare_digest(signature, hmac.new(self.key, DOMAIN+data, hashlib.sha256).hexdigest()):
            raise ValueError('commit fence MAC')
        b = shape(loads(data), ('schema','request_id','scope','ticket_digest','consumer_revision',
                               'sample_before','checked_at','flags','source_revision','decision'))
        if (canonical(b) != data or b['schema'] != 'FCI-C004-SAMPLED/1' or b['request_id'] != rid
                or b['scope'] != self.ledger.scope or b['decision'] not in ('COMMIT_FENCE_PASS',)+DENIALS):
            raise ValueError('commit fence binding')
        for name in ('consumer_revision','sample_before','checked_at'):
            integer(b[name],0)
        if b['source_revision'] is not None:
            integer(b['source_revision'],0)
        if type(b['flags']) is not list:
            raise ValueError('commit fence flags')
        mask = failures(tuple(b['flags']))
        digest = b['ticket_digest']
        if type(digest) is not str or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('commit fence digest')
        if b['decision']=='COMMIT_FENCE_PASS' and (mask or b['checked_at']<b['sample_before']):
            raise ValueError('commit fence permit')
        return b

    def _write_fence(self, b):
        data = canonical(b)
        self.db.execute('INSERT INTO commit_fence VALUES(?,?,?)',
                        (b['request_id'],data,hmac.new(self.key,DOMAIN+data,hashlib.sha256).hexdigest()))

    def _replay_guard(self, rid, entry):
        code = super()._replay_guard(rid, entry)
        fence = self._fence(rid)
        if fence is not None:
            if entry is None or fence['ticket_digest'] != ticket_digest(entry['ticket']):
                return 'BLOCK_COMMIT_FENCE_DIVERGENCE'
            if entry['status']=='DONE':
                e=entry['effect']
                if (fence['decision']!='COMMIT_FENCE_PASS' or fence['checked_at']!=e['effect_time']
                        or fence['consumer_revision']!=e['consumer_revision']):
                    return 'BLOCK_COMMIT_FENCE_DIVERGENCE'
            elif entry['status']=='PENDING' and fence['decision'] in DENIALS and code=='BLOCK_EFFECT_UNCERTAIN':
                return 'BLOCK_COMMIT_FENCE_HISTORY'
            else:
                return 'BLOCK_COMMIT_FENCE_DIVERGENCE'
        elif entry is not None and entry['status']=='DONE' and code is None:
            return 'BLOCK_COMMIT_FENCE_DIVERGENCE'
        return code

    def _finalize(self, rid, before, original, anchor, clock, conditions):
        staged=self._state(); entry=self._entry(rid)
        first=clock(); flags=conditions(); last=clock()
        mask=failures(flags)
        if not clock_ok(first) or not clock_ok(last):
            raise ValueError('commit clock unavailable')
        good,source=self._source(anchor,entry['ticket'])
        token,receipt=entry['ticket']['token']['body'],entry['ticket']['receipt']['body']
        verdict='COMMIT_FENCE_PASS'
        if first<staged.last_time or last<first:
            verdict='BLOCK_COMMIT_CLOCK'
        elif mask or staged.mask:
            verdict='BLOCK_COMMIT_CONDITIONS'
        elif not good or source.revision<=staged.authority_floor:
            verdict='BLOCK_COMMIT_SOURCE'
        elif not receipt['accepted_at']<=last<min(token['expires_at'],receipt['accepted_at']+HOLD):
            verdict='BLOCK_COMMIT_DEADLINE'
        elif ((staged.instance,staged.target,staged.policy,staged.context)!=(before.instance,before.target,before.policy,before.context)
              or staged.policy!=self.ledger.scope['policy'] or staged.context!=self.ledger.scope['context']
              or staged.level!=receipt['action']['value']):
            verdict='BLOCK_COMMIT_SCOPE'
        if verdict=='COMMIT_FENCE_PASS':
            entry['effect']['effect_time']=last
            self._write_entry(rid,entry)
            self._write_state(replace(staged,last_time=max(staged.last_time,last)))
        else:
            # All simulated writes are still uncommitted in the same SQLite
            # transaction. Restore the prior level and entry, but retain newly
            # observed fault bits and the attempt reservation in spend.db.
            restored=copy.deepcopy(original);restored['delivery']['eligible']=False
            new_mask=staged.mask|mask
            self._write_entry(rid,restored)
            self._write_state(replace(staged,level=before.level,mask=new_mask,
                                     epoch=staged.epoch+int(new_mask!=staged.mask),
                                     last_time=max(staged.last_time,first,last)))
        self._write_fence({'schema':'FCI-C004-SAMPLED/1','request_id':rid,'scope':dict(self.ledger.scope),
                           'ticket_digest':ticket_digest(entry['ticket']),'consumer_revision':staged.revision,
                           'sample_before':first,'checked_at':last,'flags':list(flags),
                           'source_revision':source.revision if source is not None else None,'decision':verdict})
        return verdict

    def finish(self, rid, anchor, clock, conditions, hook=None):
        before=self._state(); original=self._entry(rid); verdict=None; fault=None
        def bridge(point):
            nonlocal verdict,fault
            if hook:
                hook(point)
            if point=='finish_after_write':
                current=self._entry(rid)
                if original is not None and original['status']=='PENDING' and current['status']=='DONE':
                    try:
                        verdict=self._finalize(rid,before,original,anchor,clock,conditions)
                    except Exception as exc:
                        fault=exc
                        raise
                    if hook:
                        hook('after_commit_fence')  # deliberately probe residual C004
        result=super().finish(rid,anchor,clock,conditions,bridge)
        if fault is not None:
            # Do not convert an unavailable verifier into a normal denial.
            # The service poisons itself and retains the independent reservation.
            raise ValueError('commit fence unavailable') from fault
        if verdict is not None and result.code=='EFFECT_COMMITTED':
            return Result('EFFECT_COMMITTED' if verdict=='COMMIT_FENCE_PASS' else verdict,
                          self._state(),self._entry(rid),verdict=='COMMIT_FENCE_PASS')
        return result
