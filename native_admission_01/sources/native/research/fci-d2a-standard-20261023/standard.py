"""Autonomous research SQL arm; shared authorization primitives only.

No FCI decision engine, privileged repair oracle, automatic reset or provisioning
at service startup. Trusted hooks/providers are bench instrumentation, never IPC.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'fci-sql-d2a-20261023'))
from authorization import (AuthorizationRefused, bind, canonical, exact_shape,
                           require, strict_loads, verify_signature)


def clock():
    return int(time.monotonic())


def protected(path):
    """Open existing owner-only regular file, refuse links and foreign owners."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        import stat
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
                and st.st_mode & 0o077 == 0, 'FILE_PROTECTION')
        return os.read(fd, 16385)
    finally:
        os.close(fd)


def connection(path):
    protected(path)
    db = sqlite3.connect('file:'+str(path)+'?mode=rw', uri=True, isolation_level=None)
    db.execute('PRAGMA journal_mode=DELETE')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('PRAGMA busy_timeout=10000')
    return db


@contextmanager
def transaction(db):
    db.execute('BEGIN IMMEDIATE')
    try:
        yield
        db.execute('COMMIT')
    except BaseException:
        if db.in_transaction:
            db.execute('ROLLBACK')
        raise


def withdraw(db, ref):
    """Trusted resource-owner path, also callable from a separate actor process."""
    with transaction(db):
        epoch = max(db.execute('SELECT epoch FROM authority WHERE id=1').fetchone()[0],
                    ref.execute('SELECT epoch FROM control WHERE id=1').fetchone()[0])+1
        db.execute('UPDATE authority SET epoch=?,revoked=1 WHERE id=1', (epoch,))
        db.execute('INSERT INTO audit(kind,epoch) VALUES(?,?)', ('revoke',epoch))
        # Hold the resource lock through reference COMMIT so a concurrent rearm
        # cannot advance the epoch and then be overwritten by stale bookkeeping.
        # Crash between commits leaves a mismatch and blocks future admission.
        with transaction(ref):
            ref.execute('UPDATE control SET epoch=?,generation=generation+1 WHERE id=1', (epoch,))
            generation = ref.execute('SELECT generation FROM control WHERE id=1').fetchone()[0]
            ref.execute('INSERT INTO causes VALUES(?,?) ON CONFLICT(name) DO UPDATE SET occurrence=excluded.occurrence',
                        ('RESOURCE_REVOKED',generation))
    return dict(code='REVOKED', epoch=epoch)


class Standard:
    def __init__(self, runtime, provider, *, now=clock, hook=lambda point: None):
        self.runtime = Path(runtime)
        st = self.runtime.lstat()
        require(self.runtime.is_dir() and not self.runtime.is_symlink()
                and st.st_uid == os.geteuid() and st.st_mode & 0o077 == 0,
                'DIRECTORY_PROTECTION')
        self.cfg = strict_loads(protected(self.runtime/'public.json'))
        exact_shape(self.cfg, ('public_key','deployment_id','boot_id','policy_digest',
                              'context','requester_uid','maintainer_uid'))
        require(self.cfg['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'BOOT_CHANGED')
        require(type(self.cfg['requester_uid']) is int and type(self.cfg['maintainer_uid']) is int
                and self.cfg['requester_uid'] != self.cfg['maintainer_uid'], 'ROLE_CONFIG')
        self.key = bytes.fromhex(self.cfg['public_key'])
        require(len(self.key) == 32, 'PUBLIC_KEY')
        self.lock = os.open(self.runtime/'service.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            protected(self.runtime/'service.lock')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = connection(self.runtime/'resource.db')
            # This independently surviving reference is service-private, not an oracle.
            self.ref = connection(self.runtime/'reference.db')
            self.db.execute('SELECT epoch,revoked FROM authority WHERE id=1').fetchone()
            self.ref.execute('SELECT epoch,recovery,generation FROM control WHERE id=1').fetchone()
            pending = self.ref.execute("SELECT 1 FROM attempts WHERE phase='RESERVED'").fetchone()
            with transaction(self.ref):
                self.ref.execute('UPDATE control SET recovery=?,generation=generation+1 WHERE id=1',
                                 (int(bool(pending)),))
                self._cause('STARTUP')
        except BaseException:
            self.close()
            raise
        self.provider, self.now, self.hook = provider, now, hook
        self.owner = threading.get_ident()

    def close(self):
        for name in ('db','ref'):
            if hasattr(self, name):
                getattr(self,name).close()
                delattr(self,name)
        if hasattr(self,'lock'):
            os.close(self.lock)
            del self.lock

    def control(self):
        return self.ref.execute('SELECT epoch,recovery,generation FROM control WHERE id=1').fetchone()

    def _cause(self, name):
        self.ref.execute('UPDATE control SET generation=generation+1 WHERE id=1')
        generation = self.control()[2]
        self.ref.execute('INSERT INTO causes VALUES(?,?) ON CONFLICT(name) DO UPDATE SET occurrence=excluded.occurrence',
                         (name, generation))

    def sample(self):
        try:
            obs = self.provider()
            exact_shape(obs, ('flags','source_ok'))
            require(type(obs['flags']) in (list,tuple) and len(obs['flags']) == 5
                    and all(type(x) is bool for x in obs['flags'])
                    and type(obs['source_ok']) is bool, 'OBSERVATION')
            bad = ['CONDITION_'+str(i) for i,x in enumerate(obs['flags']) if not x]
            if not obs['source_ok']:
                bad.append('SOURCE')
        except Exception:
            bad = ['PROVIDER_UNAVAILABLE']
        if bad:
            with transaction(self.ref):
                for cause in bad:
                    self._cause(cause)
        return not bad

    def answer(self, code, effect='UNKNOWN', *, new=False, decision='REFUSED'):
        return dict(code=code, effect_status=effect, new_effect=new, decision=decision)

    def validate(self, req, uid, history=False):
        cfg = self.cfg
        return bind(req['authorization'], req['operation'], self.key, uid=uid,
                    role='requester', deployment_id=cfg['deployment_id'],
                    policy_digest=cfg['policy_digest'], context=cfg['context'],
                    boot_id=cfg['boot_id'], epoch=self.control()[0], now=self.now(), history=history)

    def inspect(self, rid):
        row = self.ref.execute('SELECT digest,envelope,phase FROM attempts WHERE operation_id=?', (rid,)).fetchone()
        effects = self.db.execute('SELECT digest,target,old_version,new_version,value FROM effects WHERE operation_id=?', (rid,)).fetchall()
        if row is None:
            require(not effects, 'ORPHAN_EFFECT')
            return self.answer('NO_OPERATION','NOT_COMMITTED_PROVEN')
        env = strict_loads(row[1].encode())
        require(verify_signature(env, self.key) == row[0], 'HISTORY_SIGNATURE')
        body = env['body']
        expected = (row[0],body['target'],body['expected_version'],body['expected_version']+1,body['value'])
        if effects:
            require(effects == [expected], 'HISTORY_BINDING')
            return self.answer('HISTORY', 'COMMITTED_PROVEN', decision='REPLAY')
        if row[2] == 'QUARANTINED':
            return self.answer('QUARANTINED','NOT_COMMITTED_PROVEN')
        # A missing resource row after reservation may be rollback OR restore.
        return self.answer('UNRESOLVED', 'UNKNOWN', new=None, decision='UNKNOWN')

    def execute(self, uid, req):
        exact_shape(req, ('op','operation','authorization'))
        digest = self.validate(req, uid, history=True)
        rid = req['operation']['operation_id']
        env = canonical(req['authorization']).decode()
        row = self.ref.execute('SELECT digest,envelope FROM attempts WHERE operation_id=?', (rid,)).fetchone()
        if row:
            require(row == (digest,env), 'ID_CONFLICT')
            return self.inspect(rid)
        self.validate(req, uid)
        # Persist intent before any resource modification. Never automatically retry a reservation.
        with transaction(self.ref):
            self.ref.execute('INSERT INTO attempts VALUES(?,?,?,?)', (rid,digest,env,'RESERVED'))
        self.hook('reserved')
        self.hook('before_admission')
        try:
            with transaction(self.db):
                epoch, revoked = self.db.execute('SELECT epoch,revoked FROM authority WHERE id=1').fetchone()
                control = self.control()
                require(not revoked and epoch == control[0], 'RESOURCE_AUTHORITY')
                require(not control[1] and not self.ref.execute('SELECT 1 FROM causes').fetchone(), 'LATCHED')
                self.validate(req, uid)
                require(self.sample(), 'CONDITIONS')
                self.hook('after_initial_sample')
                require(self.sample(), 'FINAL_CONDITIONS')
                self.validate(req, uid)
                # R is serialized by the same resource write lock until COMMIT.
                self.db.execute('INSERT INTO audit(kind,operation_id,epoch) VALUES(?,?,?)', ('admission',rid,epoch))
                self.hook('after_final_sample')
                body = req['authorization']['body']
                changed = self.db.execute('UPDATE configuration SET value=?,version=version+1 WHERE target=? AND version=?',
                                         (body['value'],body['target'],body['expected_version']))
                require(changed.rowcount == 1, 'SQL_PRECONDITION')
                self.db.execute('INSERT INTO effects VALUES(?,?,?,?,?,?,?)',
                                (rid,digest,env,body['target'],body['expected_version'],body['expected_version']+1,body['value']))
                self.hook('after_sql_staging')
                self.maybe_effect = True
        except AuthorizationRefused:
            self.maybe_effect = False  # context manager completed a known rollback
            with transaction(self.ref):
                self.ref.execute("UPDATE attempts SET phase='QUARANTINED' WHERE operation_id=?", (rid,))
            raise
        self.hook('after_commit')
        # A crash here leaves RESERVED but the actual signed SQL history still proves E.
        with transaction(self.ref):
            self.ref.execute("UPDATE attempts SET phase='COMMITTED' WHERE operation_id=?", (rid,))
        result = self.inspect(rid)
        require(result['effect_status'] == 'COMMITTED_PROVEN', 'COMMIT_READBACK')
        result.update(code='SQL_EFFECT_COMMITTED',new_effect=True,decision='ACCEPTED')
        return result

    def witness(self):
        # Native state token is not repair evidence. Access is restricted to maintainer.
        return dict(epoch=self.control()[0], generation=self.control()[2],
                    causes=dict(self.ref.execute('SELECT name,occurrence FROM causes ORDER BY name')))

    def rearm(self, witness, resolved):
        exact_shape(witness, ('epoch','generation','causes'))
        require(type(witness['epoch']) is int and type(witness['generation']) is int
                and type(witness['causes']) is dict and all(type(v) is int for v in witness['causes'].values()), 'WITNESS')
        require(type(resolved) is list and all(type(x) is str for x in resolved)
                and len(set(resolved)) == len(resolved), 'RESOLVED')
        # Sample before comparing so a newly observed hazard invalidates the old witness.
        require(self.sample(), 'REPAIR_CONDITIONS')
        with transaction(self.db):
            with transaction(self.ref):
                require(witness == self.witness(), 'STALE_WITNESS')
                require(set(resolved) <= set(witness['causes']), 'UNKNOWN_CAUSE')
                # Fail closed for ambiguous old attempts: retiring their rights is not
                # a proof that their past effect did not occur (including partial restore).
                for cause in resolved:
                    self.ref.execute('DELETE FROM causes WHERE name=?', (cause,))
                self.ref.execute('UPDATE control SET epoch=epoch+1,generation=generation+1,recovery=0 WHERE id=1')
                epoch = self.control()[0]
                remaining = self.ref.execute('SELECT 1 FROM causes').fetchone() is not None
            # A crash between the two commits creates an epoch mismatch, denying admission.
            self.db.execute('UPDATE authority SET epoch=?,revoked=? WHERE id=1', (epoch,int(remaining)))
            self.db.execute('INSERT INTO audit(kind,epoch) VALUES(?,?)', ('rearm',epoch))
        return dict(code='REARMED', epoch=epoch, remaining=self.witness()['causes'])

    def revoke(self):
        # The resource COMMIT, not request receipt, is R. No reversal of an existing E.
        return withdraw(self.db,self.ref)

    def handle(self, uid, raw):
        require(threading.get_ident() == self.owner, 'THREAD')
        self.maybe_effect = False
        if uid not in (self.cfg['requester_uid'],self.cfg['maintainer_uid']):
            return self.answer('BLOCK_ROLE')
        try:
            req = strict_loads(raw)
            require(type(req) is dict and type(req.get('op')) is str, 'INPUT')
            op = req['op']
            if op == 'execute':
                require(uid == self.cfg['requester_uid'], 'ROLE')
                return self.execute(uid, req)
            if op == 'inspect':
                exact_shape(req, ('op','operation_id'))
                require(type(req['operation_id']) is str, 'RID')
                return self.inspect(req['operation_id'])
            if op == 'status':
                exact_shape(req, ('op',))
                return dict(code='STATUS', epoch=self.control()[0], recovery=self.control()[1],
                            causes=self.witness()['causes'],policy=self.cfg['policy_digest'])
            require(uid == self.cfg['maintainer_uid'], 'ROLE')
            if op == 'rearm_state':
                exact_shape(req, ('op',))
                return self.witness()
            if op == 'rearm':
                exact_shape(req, ('op','witness','resolved'))
                return self.rearm(req['witness'], req['resolved'])
            if op == 'revoke':
                exact_shape(req, ('op',))
                return self.revoke()
            raise AuthorizationRefused('OP')
        except AuthorizationRefused as error:
            if self.maybe_effect:
                return self.answer('OUTCOME_UNKNOWN','UNKNOWN',new=None,decision='UNKNOWN')
            return self.answer('BLOCK_'+str(error))
        except Exception:
            # COMMIT errors and lost bookkeeping are never translated to no effect.
            with transaction(self.ref):
                self.ref.execute('UPDATE control SET recovery=1 WHERE id=1')
                self._cause('UNRESOLVED_STORAGE')
            return self.answer('OUTCOME_UNKNOWN','UNKNOWN',new=None,decision='UNKNOWN')
