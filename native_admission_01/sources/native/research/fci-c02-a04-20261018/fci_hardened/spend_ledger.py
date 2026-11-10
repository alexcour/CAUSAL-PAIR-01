"""C003 software reservation ledger. Its freshness is an explicit deployment premise.

This file is outside consumer.db's restoration domain. Co-restoring both files
can undo reservations: HMAC authenticates bytes, not their freshness. Finite,
no pruning/reset/rearm API; exhaustion blocks before a simulated effect.
"""
import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
from urllib.parse import quote

from .strict_json import canonical, loads, shape, integer

DOMAIN = b'FCI-C003-SPEND-LEDGER/1\0'
MAX_ATTEMPTS = 128
KINDS = ('EFFECT_ATTEMPT', 'CANCEL_ATTEMPT')


class SpendLedger:
    def __init__(self, path, key, scope):
        if type(key) is not bytes or len(key) != 32:
            raise ValueError('ledger key')
        self.key, self.scope = key, dict(scope)
        self.db = sqlite3.connect('file:' + quote(str(Path(path).resolve()), safe='/') + '?mode=rw',
                                  uri=True, isolation_level=None, timeout=10)
        try:
            self.db.execute('PRAGMA synchronous=FULL')
            self._read()
        except Exception:
            self.db.close()
            raise

    @classmethod
    def provision(cls, path, key, scope):
        # Offline provision only. An existing path, even empty, is never reset.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        body = {'schema': 'FCI-C003-SPEND/1', 'scope': dict(scope), 'revision': 0, 'attempts': {}}
        data = canonical(body)
        signature = hmac.new(key, DOMAIN + data, hashlib.sha256).hexdigest()
        with sqlite3.connect(path) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE ledger(id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL, signature TEXT NOT NULL)')
            db.execute('INSERT INTO ledger VALUES(1,?,?)', (data, signature))
        return cls(path, key, scope)

    def _read(self):
        rows = self.db.execute('SELECT id,payload,signature FROM ledger').fetchall()
        if len(rows) != 1 or rows[0][0] != 1:
            raise ValueError('ledger singleton missing')
        _, data, signature = rows[0]
        if type(data) is not bytes or type(signature) is not str:
            raise ValueError('ledger encoding')
        body = shape(loads(data), ('schema', 'scope', 'revision', 'attempts'))
        if canonical(body) != data or not hmac.compare_digest(signature, hmac.new(self.key, DOMAIN + data, hashlib.sha256).hexdigest()):
            raise ValueError('ledger MAC')
        if body['schema'] != 'FCI-C003-SPEND/1' or body['scope'] != self.scope or type(body['attempts']) is not dict:
            raise ValueError('ledger binding')
        if integer(body['revision'], 0, MAX_ATTEMPTS) != len(body['attempts']):
            raise ValueError('ledger revision')
        for rid, record in body['attempts'].items():
            if not rid or len(rid) > 64 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' for c in rid):
                raise ValueError('ledger request id')
            shape(record, ('ticket_digest', 'kind', 'consumer_revision'))
            digest = record['ticket_digest']
            if type(digest) is not str or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('ledger ticket digest')
            if record['kind'] not in KINDS:
                raise ValueError('ledger kind')
            integer(record['consumer_revision'], 0)
        return body

    def lookup(self, rid):
        return self._read()['attempts'].get(rid)

    def reserve(self, rid, ticket, kind, revision):
        if kind not in KINDS:
            raise ValueError('ledger kind')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            body = self._read()
            if rid in body['attempts']:
                self.db.execute('ROLLBACK')
                return False
            if body['revision'] >= MAX_ATTEMPTS:
                raise ValueError('ledger full; no automatic pruning')
            body['attempts'][rid] = {'ticket_digest': ticket_digest(ticket), 'kind': kind,
                                     'consumer_revision': integer(revision, 0)}
            body['revision'] += 1
            data = canonical(body)
            self.db.execute('UPDATE ledger SET payload=?,signature=? WHERE id=1',
                            (data, hmac.new(self.key, DOMAIN + data, hashlib.sha256).hexdigest()))
            # Durable reservation precedes consumer COMMIT. Never reversed if
            # the consumer subsequently rolls back, crashes or loses its reply.
            self.db.execute('COMMIT')
            return True
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise

    def close(self):
        self.db.close()


def ticket_digest(ticket):
    return hashlib.sha256(canonical(ticket)).hexdigest()
