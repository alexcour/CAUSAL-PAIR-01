"""Wrap preserved LIFE01 without altering its historical bytes.

A ledger reservation means ATTEMPT, never proof of effect. A pending/absent
consumer entry paired with a reservation cannot be automatically retried or
cancelled. Host/service trust and ledger non-restoration are explicit premises.
The final-observation/commit interval C004 remains open.
"""
from .vendor import Consumer
from .spend_ledger import ticket_digest
from lifecycle import Result, validate_ticket


class GuardedConsumer(Consumer):
    def __init__(self, *args, ledger, **kwargs):
        self.ledger = ledger
        super().__init__(*args, **kwargs)

    def _replay_guard(self, rid, entry):
        record = self.ledger.lookup(rid)
        if record is None:
            if entry is not None and entry['status'] in ('DONE', 'CANCELLED'):
                return 'BLOCK_LEDGER_DIVERGENCE'
            return None
        if entry is None or entry['status'] == 'PENDING':
            return 'BLOCK_EFFECT_UNCERTAIN' if record['kind'] == 'EFFECT_ATTEMPT' else 'BLOCK_CANCEL_REPLAY'
        expected = 'EFFECT_ATTEMPT' if entry['status'] == 'DONE' else 'CANCEL_ATTEMPT'
        if record['kind'] != expected or record['ticket_digest'] != ticket_digest(entry['ticket']):
            return 'BLOCK_LEDGER_DIVERGENCE'
        return None

    def receive(self, ticket, anchor, now=100, hook=None):
        t = validate_ticket(ticket, self.token_key, self.receipt_key, self.instance, self.target)
        if t is None:
            return Result('BLOCK_INPUT')
        rid = t['token']['body']['request_id']
        code = self._replay_guard(rid, self._entry(rid))
        if code:
            return Result(code)
        return super().receive(ticket, anchor, now, hook)

    def _guarded_terminal(self, operation, rid, invoke, hook):
        entry = self._entry(rid)
        code = self._replay_guard(rid, entry)
        if code:
            return Result(code)
        reserved = False

        def internal(point):
            nonlocal reserved
            if point == operation + '_after_write':
                current = self._entry(rid)
                old_status = entry['status'] if entry else None
                if current is not None and old_status not in ('DONE', 'CANCELLED') and current['status'] in ('DONE', 'CANCELLED'):
                    kind = 'EFFECT_ATTEMPT' if current['status'] == 'DONE' else 'CANCEL_ATTEMPT'
                    if not self.ledger.reserve(rid, current['ticket'], kind, self._state().revision):
                        raise ValueError('reservation already present')
                    reserved = True
            if hook:
                hook(point)  # trusted test instrumentation, never IPC input

        result = invoke(internal)
        if reserved and result.code in ('BLOCK_STORAGE', 'OUTCOME_UNKNOWN'):
            return Result('OUTCOME_UNKNOWN_EFFECT' if operation == 'finish' else 'OUTCOME_UNKNOWN_CANCEL')
        return result

    def finish(self, rid, anchor, clock, conditions, hook=None):
        return self._guarded_terminal('finish', rid,
            lambda internal: super(GuardedConsumer, self).finish(rid, anchor, clock, conditions, internal), hook)

    def cancel(self, ticket, now=100, reason='RETIRE_PENDING', hook=None):
        t = validate_ticket(ticket, self.token_key, self.receipt_key, self.instance, self.target)
        if t is None:
            return Result('BLOCK_INPUT')
        rid = t['token']['body']['request_id']
        return self._guarded_terminal('cancel', rid,
            lambda internal: super(GuardedConsumer, self).cancel(ticket, now, reason, internal), hook)
