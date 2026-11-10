"""Research fixture: authoritative full-state anchor, conditional on independence.

Two SQLite files on one machine DO NOT enforce an independent trust boundary.
No actuator permit, recovery of lost anchor, or key rotation is implemented.
"""
from __future__ import annotations

import hmac
import json
import os
import sqlite3
from dataclasses import asdict, replace
from pathlib import Path
from urllib.parse import quote

from base01.authority import (Authority, State, Decision, StorageError, STARTUP,
                              canonical, mac)


class AnchorError(StorageError):
    pass


class FreshnessError(StorageError):
    pass


def open_existing(path):
    uri = "file:" + quote(str(Path(path).resolve()), safe="/") + "?mode=rw"
    db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=10)
    db.execute("PRAGMA synchronous=FULL")
    return db


def rollback(db):
    try:
        if db.in_transaction:
            db.execute("ROLLBACK")
    except sqlite3.Error:
        pass


class SQLiteAnchor:
    """Fixture API. Environment must prevent rollback/reset of this database.

    CAS durable commit is the state transition linearization point. Complete
    state equality, including revision, prevents stale successful proposals.
    Public test keys are deliberately not production key material.
    """
    def __init__(self, path, key, instance):
        if type(key) is not bytes or len(key) < 32:
            raise ValueError("anchor key requires at least 32 bytes")
        self.key, self.instance = key, instance
        try:
            self.db = open_existing(path)
            self.read()
        except (sqlite3.Error, ValueError, TypeError, KeyError, AnchorError) as exc:
            if hasattr(self, "db"):
                self.db.close()
            raise AnchorError("unavailable or unauthenticated anchor") from exc

    @classmethod
    def provision(cls, path, key, initial):
        initial.validate()
        if type(key) is not bytes or len(key) < 32:
            raise ValueError("invalid anchor key")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        data = asdict(initial)
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE anchor (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, signature TEXT NOT NULL)")
            db.execute("INSERT INTO anchor VALUES(1,?,?)", (canonical(data).decode(), mac(key, b"FCI-REPAIR-03/ANCHOR\0", data)))
        return cls(path, key, initial.instance)

    def _read(self):
        rows = self.db.execute("SELECT payload, signature FROM anchor").fetchall()
        if len(rows) != 1:
            raise ValueError("exactly one anchor required")
        data, sig = json.loads(rows[0][0]), rows[0][1]
        if not hmac.compare_digest(sig, mac(self.key, b"FCI-REPAIR-03/ANCHOR\0", data)):
            raise ValueError("anchor authentication failed")
        state = State(**data)
        state.validate()
        if state.instance != self.instance:
            raise ValueError("wrong anchor identity")
        return state

    def read(self):
        try:
            return self._read()
        except (sqlite3.Error, ValueError, TypeError, KeyError) as exc:
            raise AnchorError("anchor read failed") from exc

    def cas(self, expected, proposed):
        expected.validate()
        proposed.validate()
        if (expected.instance != self.instance or proposed.instance != self.instance
                or proposed.revision != expected.revision + 1
                or proposed.epoch < expected.epoch):
            raise AnchorError("invalid successor")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            if self._read() != expected:
                raise FreshnessError("stale anchor proposal")
            data = asdict(proposed)
            self.db.execute("UPDATE anchor SET payload=?, signature=? WHERE id=1", (canonical(data).decode(), mac(self.key, b"FCI-REPAIR-03/ANCHOR\0", data)))
            self.db.execute("COMMIT")
        except (sqlite3.Error, ValueError, TypeError, KeyError, FreshnessError) as exc:
            rollback(self.db)
            if isinstance(exc, FreshnessError):
                raise
            raise AnchorError("anchor commit failed") from exc

    def close(self):
        self.db.close()


class AnchoredAuthority(Authority):
    """Inherited pure latch/witness rules, new persistence/refinement boundary.

    hook labels are explicit test fault-injection points. In normal operation
    there is no hook. Recovery is a maintenance operation, never permission.
    """
    def __init__(self, path, state_key, rearm_key, instance, anchor, hook=None):
        self._attach(path, state_key, rearm_key, instance, anchor, hook)
        decision = self._run(self._startup)
        if decision.code != "STARTUP_RECORDED":
            self.close()
            raise StorageError(decision.code)

    def _attach(self, path, state_key, rearm_key, instance, anchor, hook):
        if (type(state_key) is not bytes or type(rearm_key) is not bytes
                or min(len(state_key), len(rearm_key)) < 32
                or len({state_key, rearm_key, anchor.key}) != 3
                or anchor.instance != instance):
            raise ValueError("three distinct keys and matching identity required")
        self.state_key, self.rearm_key, self.instance = state_key, rearm_key, instance
        self.anchor, self.hook = anchor, hook
        try:
            self.db = open_existing(path)
        except sqlite3.Error as exc:
            raise StorageError("replica unavailable") from exc

    @staticmethod
    def _startup(state):
        return Decision("STARTUP_RECORDED", replace(state, mask=state.mask | STARTUP,
                        epoch=state.epoch + 1, revision=state.revision + 1))

    @classmethod
    def bootstrap(cls, path, state_key, rearm_key, instance, policy, context, anchor):
        if min(len(state_key), len(rearm_key)) < 32 or len({state_key, rearm_key, anchor.key}) != 3:
            raise ValueError("three distinct keys required")
        initial = State(instance, policy, context, STARTUP, 0, 0)
        initial.validate()
        if anchor.read() != initial:
            raise FreshnessError("bootstrap requires exactly provisioned initial anchor")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE authority (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, signature TEXT NOT NULL)")
            data = asdict(initial)
            db.execute("INSERT INTO authority VALUES(1,?,?)", (canonical(data).decode(), mac(state_key, b"FCI-REPAIR-01/STATE\0", data)))
        return cls(path, state_key, rearm_key, instance, anchor)

    def _point(self, label):
        if self.hook is not None:
            self.hook(label)

    def _commit_pair(self, old, decision):
        assert decision.state is not None
        self._point("before_anchor")
        self.anchor.cas(old, decision.state)
        self._point("after_anchor")
        # Normal writes and recovery both require the fixed existing schema.
        data = asdict(decision.state)
        self.db.execute("INSERT OR REPLACE INTO authority VALUES(1,?,?)", (canonical(data).decode(), mac(self.state_key, b"FCI-REPAIR-01/STATE\0", data)))
        self._point("after_replica_write")
        self.db.execute("COMMIT")
        self._point("after_replica_commit")
        return decision

    def _run(self, operation):
        try:
            self.db.execute("BEGIN IMMEDIATE")
            local = self._read()
            anchored = self.anchor.read()
            if local != anchored:
                raise FreshnessError("replica differs from authoritative anchor")
            return self._commit_pair(anchored, operation(anchored))
        except FreshnessError:
            rollback(self.db)
            return Decision("BLOCK_FRESHNESS", None)
        except AnchorError:
            rollback(self.db)
            return Decision("BLOCK_ANCHOR", None)
        except (sqlite3.Error, ValueError, TypeError, KeyError, OverflowError):
            rollback(self.db)
            return Decision("BLOCK_STORAGE", None)

    def state(self):
        local = self._read()
        if local != self.anchor.read():
            raise FreshnessError("replica not current")
        return local

    @classmethod
    def recover(cls, path, state_key, rearm_key, instance, anchor, hook=None):
        """Existing replica schema only. No reset or recovery of lost anchor.

        Caller explicitly chooses maintenance; full state comes only from
        anchor, never from arbitrary caller-provided recovery data.
        """
        obj = cls.__new__(cls)
        try:
            obj._attach(path, state_key, rearm_key, instance, anchor, hook)
            obj.db.execute("BEGIN IMMEDIATE")
            old = anchor.read()
            nxt = cls._startup(old).state
            return obj._commit_pair(old, Decision("RECOVERY_LOCKED", nxt))
        except FreshnessError:
            return Decision("BLOCK_FRESHNESS", None)
        except AnchorError:
            return Decision("BLOCK_ANCHOR", None)
        except (StorageError, sqlite3.Error, ValueError, TypeError, KeyError, OverflowError):
            return Decision("BLOCK_STORAGE", None)
        finally:
            if hasattr(obj, "db"):
                rollback(obj.db)
                obj.close()
