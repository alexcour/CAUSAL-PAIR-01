"""Read-only lab snapshots. No API execute/rearm/repair or new connections at fork."""
from dataclasses import asdict
import os
from pathlib import Path
import sqlite3
import time


def scalar(value):
    if isinstance(value, bytes):
        return {'bytes_hex': value.hex()}
    return value


def root_snapshot(runtime, profile):
    names = ('consumer.db', 'spend.db', 'anchor.db', 'replica.db') if profile == 'FCI' else ('resource.db', 'reference.db')
    stores = {}
    for name in names:
        with sqlite3.connect('file:' + str(Path(runtime) / name) + '?mode=ro', uri=True, isolation_level=None, timeout=10) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            tables = {}
            for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall():
                quoted = '"' + table.replace('"', '""') + '"'
                columns = [x[1] for x in db.execute('PRAGMA table_info(' + quoted + ')')]
                rows = [[scalar(x) for x in row] for row in db.execute('SELECT * FROM ' + quoted + ' ORDER BY 1')]
                tables[table] = dict(columns=columns, rows=rows)
            db.rollback()
            stores[name] = tables
    return dict(stores=stores, reader_uid=os.getuid(), reader_pid=os.getpid(), ns=time.monotonic_ns(),
                read_only=True, atomic_across_databases=False)


def actor_snapshot(bridge):
    if bridge.db.in_transaction:
        raise ValueError('SNAPSHOT_EXPECTS_IDLE_NATIVE_CONNECTION')
    value = dict(sql=root_snapshot(bridge.runtime, bridge.profile))
    if bridge.profile == 'FCI':
        c = bridge.engine.consumer
        history = c.history()
        ids = [x['ticket']['token']['body']['request_id'] for x in history]
        value['authenticated_in_owner'] = dict(
            consumer=asdict(c._state()), history=history,
            fences={rid: c._fence(rid) for rid in ids}, spend=c.ledger._read())
        value['MAC_validation'] = 'FROZEN_NATIVE_DECODERS_IN_TRUSTED_OWNER_NOT_INDEPENDENT_OFFLINE_MAC_AUDIT'
    else:
        value['authenticated_in_owner'] = None
        value['MAC_validation'] = 'NOT_APPLICABLE_STANDARD'
    return value
