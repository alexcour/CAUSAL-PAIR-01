"""Offline provisioning only. Production migration/repair is deliberately absent."""
import json
from pathlib import Path
import sqlite3


def provision(runtime, public_config):
    root = Path(runtime)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root/'public.json').write_text(json.dumps(public_config,sort_keys=True))
    (root/'public.json').chmod(0o600)
    (root/'service.lock').touch(mode=0o600)
    schemas = {
        'resource.db': '''
          CREATE TABLE authority(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL,revoked INTEGER NOT NULL);
          INSERT INTO authority VALUES(1,0,0);
          CREATE TABLE configuration(target TEXT PRIMARY KEY,version INTEGER NOT NULL,value INTEGER NOT NULL);
          INSERT INTO configuration VALUES('synthetic-config',0,0),('synthetic-config-decoy',0,0);
          CREATE TABLE effects(operation_id TEXT PRIMARY KEY,digest TEXT NOT NULL,envelope TEXT NOT NULL,
            target TEXT NOT NULL,old_version INTEGER NOT NULL,new_version INTEGER NOT NULL,value INTEGER NOT NULL);
          CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,operation_id TEXT,epoch INTEGER NOT NULL);
        ''',
        'reference.db': '''
          CREATE TABLE control(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL,recovery INTEGER NOT NULL,generation INTEGER NOT NULL);
          INSERT INTO control VALUES(1,0,0,0);
          CREATE TABLE attempts(operation_id TEXT PRIMARY KEY,digest TEXT NOT NULL,envelope TEXT NOT NULL,phase TEXT NOT NULL);
          CREATE TABLE causes(name TEXT PRIMARY KEY,occurrence INTEGER NOT NULL);
        '''}
    for name, schema in schemas.items():
        path = root/name
        with sqlite3.connect(path) as db:
            db.executescript(schema)
        path.chmod(0o600)
