"""Versioned trusted-owner participant; never accepts a caller-supplied proof.

This changes execution bindings, not the frozen engine files. Sealed signals are
created only at the pinned admit/check boundary and consumed at the native txn.
"""
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import threading
import uuid

DOMAIN = b'FCI-TYPED-GUARD-ROLLBACK/1\0'

# Trusted-owner scope only. All participants using these temporary bindings
# must share this module instance. A failed restoration requires process restart.
_SCOPE_LOCK = threading.Lock()
_SCOPE_BROKEN = False


def need(ok, code):
    if not ok:
        raise ValueError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def tables(db):
    out = {}
    for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall():
        q = '"' + name.replace('"', '""') + '"'
        out[name] = dict(columns=[x[1] for x in db.execute('PRAGMA table_info(' + q + ')')],
            rows=[[{'bytes_hex': x.hex()} if type(x) is bytes else x for x in row]
                  for row in db.execute('SELECT * FROM ' + q + ' ORDER BY 1')])
    return out


def fresh(path):
    with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True, isolation_level=None, timeout=10) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        answer = tables(db)
        db.rollback()
        return answer


class Participant:
    def __init__(self, bridge, *, case='FENCE_FIRST'):
        from native_bridge import NativeBridge
        self.b, self.case = bridge, case
        self.guard_original = bridge.admit
        need(getattr(self.guard_original, '__func__', None) is NativeBridge.admit and
             getattr(bridge.check, '__func__', None) is NativeBridge.check, 'PINNED_GUARD_METHODS')
        self.guard_code = NativeBridge.admit.__code__
        self.check_code = NativeBridge.check.__code__
        self.require_code = bridge.auth.require.__code__
        self.events, self.pre, self.post = [], None, None
        self.rollback_returned = False
        self.commit_boundary = False
        self.transaction_id = None
        self.invocation = self.request_digest = self.receipt = None
        self._owner_thread = threading.get_ident()
        self._started = self._restore_failed = self.scope_restored = False
        self.seal = object()
        participant = self
        base = bridge.auth.AuthorizationRefused if bridge.profile == 'STANDARD' else BaseException

        class SealedGuardSignal(base):
            def __init__(signal, seal):
                need(seal is participant.seal, 'PRIVATE_PARTICIPANT_SIGNAL')
                super().__init__('STALE_ATTEMPT')
                signal.owner = participant
        self.signal_type = SealedGuardSignal

    def event(self, kind, **data):
        self.events.append(dict(event=kind, ns=time.monotonic_ns(), pid=os.getpid(), uid=os.getuid(), **data))

    def _begin(self):
        need(self.b.db.in_transaction and self.transaction_id is None, 'ACTUAL_NATIVE_TRANSACTION_ENTRY')
        self.transaction_id = uuid.uuid4().hex
        self.pre = None if self.case == 'INCOMPLETE_WITNESS' else tables(self.b.db)
        if self.b.profile == 'FCI':
            self.spend_before = self.b.engine.consumer.ledger._read()
        else:
            self.spend_before = None
        self.event('NATIVE_TRANSACTION_ENTERED', in_transaction=True, transaction=self.transaction_id,
                   preimage_complete=self.pre is not None)

    def _guard(self, db, request, uid):
        self.event('PINNED_ADMIT_ENTER', in_transaction=db.in_transaction)
        if self.case == 'OTHER_EXCEPTION':
            # Trusted bench control: same text, wrong type and no frozen guard origin.
            raise ValueError('STALE_ATTEMPT')
        try:
            return self.guard_original(db, request, uid)
        except self.b.auth.AuthorizationRefused as exc:
            codes = []
            tb = exc.__traceback__
            while tb is not None:
                codes.append(tb.tb_frame.f_code)
                tb = tb.tb_next
            qualified_origin = (type(exc) is self.b.auth.AuthorizationRefused and str(exc) == 'STALE_ATTEMPT'
                and self.guard_code in codes and self.check_code in codes and self.require_code in codes
                and db is self.b.db and db.in_transaction and self.transaction_id is not None
                and self.b.active is not None and self.b.active[1] == uid
                and digest(self.b.active[0]) == self.request_digest == digest(request))
            self.event('PINNED_ADMIT_RAISED', exception_module=type(exc).__module__,
                exception_type=type(exc).__name__, code=str(exc), origin_received=qualified_origin,
                in_transaction=db.in_transaction, exception_runtime_identity=id(exc))
            if not qualified_origin:
                raise
            self.signal = self.signal_type(self.seal)
            raise self.signal from exc

    def _settle(self, signal):
        need(type(signal) is self.signal_type and signal is self.signal and signal.owner is self,
             'SAME_SEALED_SIGNAL_INVOCATION')
        self.event('ROLLBACK_ATTEMPT', in_transaction=self.b.db.in_transaction,
                   commit_boundary=self.commit_boundary)
        deny = self.case == 'ROLLBACK_DENIED'
        if deny:
            def authorizer(action, first, second, database, trigger):
                if action == sqlite3.SQLITE_TRANSACTION and first == 'ROLLBACK':
                    self.event('REAL_SQLITE_ROLLBACK_DENIED')
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            self.b.db.set_authorizer(authorizer)
        try:
            self.b.db.execute('ROLLBACK')
            self.rollback_returned = True
            self.event('ROLLBACK_RETURNED', in_transaction=self.b.db.in_transaction)
        except Exception as exc:
            self.rollback_returned = False
            self.event('ROLLBACK_FAILED', exception_type=type(exc).__name__, message=str(exc))
        finally:
            if deny:
                self.b.db.set_authorizer(None)
        if self.b.db.in_transaction:
            # Abort cleanup never repairs a failed first rollback attestation.
            self.b.db.rollback()
            self.event('ABORT_CLEANUP_RETURNED', in_transaction=self.b.db.in_transaction)
        self.post = fresh(self.b.path)
        self.event('FRESH_DURABLE_READBACK', in_transaction=self.b.db.in_transaction,
                   matches_preimage=self.pre is not None and self.post == self.pre)

    def _fci_transaction(self, original, operation, fn, hook=None, anchor=None):
        if operation != 'finish':
            return original(operation, fn, hook, anchor)
        def inside(point):
            self._begin()
            return fn(point)
        def tracking(point):
            if point == 'finish_after_write':
                self.commit_boundary = True
                self.event('COMMIT_BOUNDARY_REACHED')
            if hook is not None:
                hook(point)
            if point == 'finish_after_write' and self.case == 'POST_RESERVATION_ABORT':
                self.event('POST_RESERVATION_ABORT', B_record_present=self.b.engine.consumer.ledger.lookup(self.rid) is not None)
                raise OSError('INJECTED_AFTER_RESERVATION_BEFORE_COMMIT')
        try:
            return original(operation, inside, tracking, anchor)
        except self.signal_type as signal:
            self._settle(signal)
            raise

    @contextmanager
    def _standard_transaction(self, original, db):
        if db is not self.b.db:
            with original(db):
                yield
            return
        with original(db):
            self._begin()
            try:
                yield
            except self.signal_type as signal:
                self._settle(signal)
                raise  # Standard's real except AuthorizationRefused still quarantines B.

    def _receipt(self):
        from handoff import canonical, content_hash, key_text, public, signed, verify
        from certified_bridge import DOMAIN as CERT_DOMAIN, FIELDS
        from native_bridge import PERMIT
        b = self.b
        need(self.rollback_returned and not self.commit_boundary and self.pre is not None and
             self.pre == self.post and not b.db.in_transaction, 'ROLLBACK_AND_PREIMAGE_NOT_QUALIFIED')
        p = verify(self.request['permit'], public(b.sink_key), PERMIT)
        native = verify(self.request['native']['authorization'], public(b.signer), b.auth.DOMAIN)
        need(p['native_digest'] == digest(self.request['native']) and p['native_operation_id'] == self.rid and
             p['subject_uid'] == native['subject_uid'] == self.uid == 62024 and p['generation'] == 2,
             'SIGNED_REQUEST_BINDING')
        need(p['key']['deployment'] == b.deployment and p['key']['sink'] == b.profile and
             native['deployment_id'] == b.deployment and native['operation_id'] == self.rid and
             native['policy_digest'] == p['policy'] == b.policy, 'DEPLOYMENT_POLICY_BINDING')
        native_epoch = b.engine.meta()['epoch'] if b.profile == 'FCI' else b.engine.control()[0]
        now = int(time.monotonic())
        need(native['authority_epoch'] == native_epoch and native['not_before'] <= now < native['not_after'] and
             p['not_before'] <= b.now() < p['not_after'], 'CURRENT_NATIVE_EPOCH_AND_VALIDITY')
        with sqlite3.connect('file:' + str(b.path) + '?mode=ro', uri=True, isolation_level=None) as db:
            db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
            kt = key_text(p['key'])
            policy, epoch, revoked = b.control(db)
            business = b.business(db, kt, p['content_hash'])
            need(not revoked and policy == p['policy'] == b.policy and epoch == p['epoch'] and
                 business[2] is None and content_hash(json.loads(business[0])) == p['content_hash'],
                 'CURRENT_AUTHORITY_OR_RESULT')
            need(b.latest(db, kt) == (2, p['attempt_id'], self.uid, self.rid, 'FENCED'), 'CURRENT_B_FENCE')
            b.no_unrecorded_effect(db, kt)
            record = db.execute('SELECT id,envelope,redeemed,allocation FROM sk_certificates WHERE k=? AND g=2', (kt,)).fetchone()
            need(record is not None and record[2:] == (0, None), 'B_CERTIFICATE_UNUSED')
            certificate = json.loads(record[1]); cert = verify(certificate, public(b.sink_key), CERT_DOMAIN)
            need(set(cert) == set(FIELDS) and cert['schema'] == 'NATIVE-NONEXECUTION-CERTIFICATE/1' and
                 cert['disposition'] == 'NONEXECUTION_FENCED' and cert['certificate_id'] == record[0] and
                 cert['key'] == p['key'] and cert['content_hash'] == p['content_hash'] and
                 cert['fenced_generation'] == 2 and cert['fenced_attempt_id'] == p['attempt_id'] and
                 cert['fenced_subject_uid'] == self.uid and cert['fenced_native_operation_id'] == self.rid and
                 cert['sink_public'] == public(b.sink_key) and cert['policy'] == policy and cert['epoch_at_fence'] == epoch,
                 'EXACT_CERTIFICATE_BINDING')
            db.rollback()
        if b.profile == 'FCI':
            consumer = b.engine.consumer
            spend = consumer.ledger._read()
            need(self.spend_before == spend and self.rid not in spend['attempts'], 'SPEND_B_PRESENT_OR_CHANGED')
            entry = consumer._entry(self.rid)
            need(entry is not None and entry['status'] == 'PENDING' and consumer._fence(self.rid) is None,
                 'NATIVE_B_CONSUMER_OR_FENCE')
            spend_status = 'B_ABSENT'
        else:
            need(b.engine.ref.execute('SELECT phase FROM attempts WHERE operation_id=?',(self.rid,)).fetchone()==('QUARANTINED',),
                 'STANDARD_NATIVE_QUARANTINE')
            spend_status = 'NOT_APPLICABLE'
        return signed(b.sink_key, DOMAIN, dict(schema='NATIVE-TYPED-GUARD-ROLLBACK/1',
            profile=b.profile, key=p['key'], content_hash=p['content_hash'], rid=self.rid, generation=2, uid=self.uid,
            request_digest=self.request_digest, invocation=self.invocation, transaction=self.transaction_id,
            policy=policy, epoch=epoch, deployment=b.deployment, inode=os.stat(b.path).st_ino,
            certificate_id=record[0], certificate_digest=digest(certificate),
            guard_type='authorization.AuthorizationRefused', guard_code='STALE_ATTEMPT',
            guard_site='NativeBridge.admit/NativeBridge.check', rollback_returned=True, commit_boundary=False,
            preimage_digest=digest(self.pre), durable_postimage_digest=digest(self.post),
            spend_status=spend_status, participant_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            execution_authorized=False, recovery_authorized=False, independent_attestation=False))

    def _bind(self, stack, owner, name, value):
        """Register cleanup before a setter that may mutate then raise."""
        had_value = name in vars(owner)
        old_value = vars(owner).get(name)
        def restore():
            global _SCOPE_BROKEN
            try:
                if had_value:
                    setattr(owner, name, old_value)
                elif name in vars(owner):
                    delattr(owner, name)
            except BaseException:
                # ExitStack still attempts every other registered cleanup.
                self._restore_failed = True
                _SCOPE_BROKEN = True
                raise
        stack.callback(restore)
        setattr(owner, name, value)

    def execute(self, request, uid, *, after_precheck=lambda: None):
        # Reject before touching the thread-affine SQLite connection or bindings.
        need(threading.get_ident() == self._owner_thread, 'PARTICIPANT_OWNER_THREAD')
        need(not self._started, 'FRESH_OWNER_INVOCATION')
        self._started = True
        need(_SCOPE_LOCK.acquire(blocking=False), 'PARTICIPANT_SCOPE_BUSY')
        try:
            need(not _SCOPE_BROKEN, 'PARTICIPANT_SCOPE_BROKEN')
            return self._execute_scoped(request, uid, after_precheck=after_precheck)
        finally:
            _SCOPE_LOCK.release()

    def _execute_scoped(self, request, uid, *, after_precheck):
        b = self.b
        need(b.active is None and not b.db.in_transaction and self.transaction_id is None, 'FRESH_OWNER_INVOCATION')
        self.invocation, self.request, self.uid = uuid.uuid4().hex, request, uid
        self.request_digest = digest(request)
        self.rid = request['permit']['body']['native_operation_id']
        self.event('INVOCATION_ENTERED', invocation=self.invocation, request_digest=self.request_digest)
        phase = 'INSTALLING'
        try:
            with ExitStack() as stack:
                self._bind(stack, b, 'admit', self._guard)
                if b.profile == 'FCI':
                    consumer = b.engine.consumer
                    original = consumer._transaction
                    self._bind(stack, consumer, '_transaction',
                        lambda operation, fn, hook=None, anchor=None:
                            self._fci_transaction(original, operation, fn, hook, anchor))
                else:
                    import standard
                    original = standard.transaction
                    original_hook = b.engine.hook
                    def observed_hook(point):
                        if point == 'after_sql_staging':
                            self.commit_boundary = True
                            self.event('COMMIT_BOUNDARY_REACHED')
                        return original_hook(point)
                    self._bind(stack, b.engine, 'hook', observed_hook)
                    self._bind(stack, standard, 'transaction',
                        lambda db: self._standard_transaction(original, db))
                phase = 'EXECUTING'
                result = self._execute_installed(request, uid, after_precheck=after_precheck)
                phase = 'RESTORING'
            # Publish a witness only after all temporary bindings are restored.
            self.scope_restored = True
            self.event('PARTICIPANT_RESTORED', native_in_transaction=b.db.in_transaction)
            self.receipt = result.get('refusal_witness')
            return result
        except Exception as exc:
            self.receipt = None
            self.event('PARTICIPANT_SCOPE_HELD', phase=phase,
                restoration_failed=self._restore_failed, exception_type=type(exc).__name__, reason=str(exc))
            return dict(status='HOLD_NATIVE', code='PARTICIPANT_SCOPE_FAILURE',
                phase=phase, restoration_failed=self._restore_failed,
                execution_authorized=False, recovery_authorized=False)
        except BaseException:
            self.receipt = None
            raise

    def _execute_installed(self, request, uid, *, after_precheck):
        b = self.b
        try:
            result = b.execute(request, uid, after_precheck=after_precheck)
            self.event('NATIVE_API_RETURNED', status=result['status'])
            return result
        except self.signal_type:
            receipt = None
            try:
                receipt = self._receipt()
                self.event('RECEIPT_QUALIFIED')
            except Exception as exc:
                self.event('RECEIPT_HELD', exception_type=type(exc).__name__, reason=str(exc))
            # Keep the original FCI conservative hold. Never reset any native flag.
            native_hold = b.engine.unknown() if b.profile == 'FCI' else None
            if receipt is None:
                return dict(status='HOLD_NATIVE', code='REFUSAL_PROOF_NOT_QUALIFIED', native=native_hold)
            return dict(status='REFUSED', code='STALE_ATTEMPT', refusal_witness=receipt,
                availability='NOT_QUALIFIED', execution_authorized=False, recovery_authorized=False,
                native_hold=native_hold)
        except Exception as exc:
            # A different native error never becomes a proven stale refusal.
            self.event('UNCLASSIFIED_NATIVE_EXCEPTION', exception_type=type(exc).__name__, message=str(exc))
            hold = b.engine.unknown() if b.profile == 'FCI' else None
            return dict(status='HOLD_NATIVE', code='UNCLASSIFIED_NATIVE_EXCEPTION', native=hold)

    def evidence(self):
        return dict(schema='NATIVE-REFUSAL-PARTICIPANT-EVIDENCE/1', invocation=self.invocation,
            transaction=self.transaction_id, request_digest=self.request_digest, events=self.events,
            preimage=self.pre, durable_postimage=self.post, rollback_returned=self.rollback_returned,
            commit_boundary=self.commit_boundary, receipt=getattr(self,'receipt',None),
            scope_restored=self.scope_restored, restoration_failed=self._restore_failed,
            factory_is_new=True, engine_files_changed=False)
