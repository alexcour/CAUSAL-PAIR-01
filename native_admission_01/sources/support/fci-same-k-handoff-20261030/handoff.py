"""Private research prototype: same business K, different signed A/B permits.

Trust assumptions: retained SQLite destination, all business writes through this
API, authenticated principal arguments supplied by a trusted caller. No RPC/OS
isolation, physical effect, native-engine integration or rollback resistance.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PERMIT_DOMAIN = b"FCI-SAME-K-PERMIT/2\x00"
ALLOCATION_DOMAIN = b"FCI-SAME-K-ALLOCATION/1\x00"
RESULT_DOMAIN = b"FCI-SAME-K-RESULT/1\x00"
RESOLUTION_DOMAIN = b"FCI-SAME-K-RESOLUTION/1\x00"
CONTENT_DOMAIN = b"FCI-SAME-K-CONTENT/1\x00"
POLICY = "same-k-lab-v1"


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def canonical(value):
    def check(x):
        need(x is None or type(x) in (str, int, bool, list, dict), "JSON_TYPE")
        if type(x) is dict:
            need(all(type(k) is str for k in x), "JSON_KEY")
            for v in x.values():
                check(v)
        elif type(x) is list:
            for v in x:
                check(v)
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def strict_loads(raw):
    need(type(raw) is bytes and len(raw) <= 65536, "FRAME")
    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, "DUPLICATE_KEY")
            out[k] = v
        return out
    def bad(_):
        raise Refused("JSON_NUMBER")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=bad, parse_constant=bad)
        canonical(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Refused("JSON") from exc


def shape(obj, fields):
    need(type(obj) is dict and set(obj) == set(fields), "SHAPE")


def text_field(x):
    return type(x) is str and 0 < len(x) <= 256 and x.isascii()


def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def signed(key, domain, body):
    return {"body": body, "signature": key.sign(domain + canonical(body)).hex()}


def verify(envelope, public_hex, domain):
    shape(envelope, ("body", "signature"))
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            bytes.fromhex(envelope["signature"]), domain + canonical(envelope["body"]))
    except Refused:
        raise
    except Exception as exc:
        raise Refused("SIGNATURE") from exc
    return envelope["body"]


def key_text(k):
    shape(k, ("scope", "deployment", "sink", "operation_id"))
    need(all(text_field(v) for v in k.values()), "KEY")
    return canonical(k).decode()


def content_hash(content):
    shape(content, ("schema", "action", "target", "expected_version", "value"))
    need(content["schema"] == "SQL-SET/1" and content["action"] == "set_value", "CONTENT_SCHEMA")
    need(text_field(content["target"]), "TARGET")
    need(type(content["expected_version"]) is int and 0 <= content["expected_version"] < 2**62, "VERSION")
    need(type(content["value"]) is int and -(2**62) <= content["value"] < 2**62, "VALUE")
    return hashlib.sha256(CONTENT_DOMAIN + canonical(content)).hexdigest()


def issue_permit(allocation, issuer_key, sink_public, now, ttl=60):
    """Trusted issuer operation; allocation is committed and signed by the sink."""
    b = verify(allocation, sink_public, ALLOCATION_DOMAIN)
    shape(b, ("action", "key", "content_hash", "generation", "attempt_id", "subject", "policy", "epoch", "sink_public", "issuer_public"))
    need(b["action"] == "ALLOCATED" and b["sink_public"] == sink_public, "ALLOCATION")
    need(b["issuer_public"] == public(issuer_key), "ISSUER")
    need(type(now) is int and type(ttl) is int and 0 < ttl <= 300, "VALIDITY")
    return signed(issuer_key, PERMIT_DOMAIN, dict(b, action="EXECUTE", schema="PERMIT/2", not_before=now, not_after=now+ttl))


class Destination:
    def __init__(self, path, sink_key, clock=None, fault=None):
        self.path = Path(path).resolve()
        need(self.path.is_file(), "STORE_MISSING_NO_RESET")
        self.key = sink_key
        self.clock = clock or (lambda: int(time.time()))
        self.fault = fault or (lambda stage: None)
        with self.connection() as db:
            self.meta = dict(db.execute("SELECT name,value FROM meta"))
            need(self.meta.get("schema") == "SAME-K/1", "STORE_SCHEMA")
            need(self.meta.get("sink_public") == public(sink_key), "SINK_IDENTITY")

    @classmethod
    def provision(cls, path, sink_key, issuer_public, *, controller="controller", sink="sink-1", target="configuration", value=0, version=4):
        p = Path(path).resolve()
        need(not p.exists(), "STORE_ALREADY_EXISTS")
        need(all(text_field(v) for v in (controller, sink, target)), "PROVISION")
        need(type(value) is int and type(version) is int and version >= 0, "PROVISION")
        p.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation prevents accidental replacement of a retained store.
        with p.open("xb"):
            pass
        with sqlite3.connect(p) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.executescript("""
                CREATE TABLE meta(name TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE resources(target TEXT PRIMARY KEY,value INTEGER NOT NULL,version INTEGER NOT NULL);
                CREATE TABLE operations(k TEXT PRIMARY KEY,content TEXT NOT NULL,h TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('BOUND','DONE')),result TEXT);
                CREATE TABLE attempts(k TEXT NOT NULL,g INTEGER NOT NULL,attempt_id TEXT UNIQUE NOT NULL,subject TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('OPEN','FENCED','APPLIED')),PRIMARY KEY(k,g),FOREIGN KEY(k) REFERENCES operations(k));
                CREATE UNIQUE INDEX one_open ON attempts(k) WHERE state='OPEN';
                CREATE TABLE allocations(request_id TEXT PRIMARY KEY,parameters TEXT NOT NULL,k TEXT NOT NULL,g INTEGER NOT NULL);
                CREATE TABLE readers(k TEXT NOT NULL,subject TEXT NOT NULL,PRIMARY KEY(k,subject));
                CREATE TABLE effects(k TEXT PRIMARY KEY,effect_id TEXT UNIQUE NOT NULL,result TEXT NOT NULL,FOREIGN KEY(k) REFERENCES operations(k));
                CREATE TABLE events(seq INTEGER PRIMARY KEY,kind TEXT NOT NULL,k TEXT NOT NULL,data TEXT NOT NULL);
            """)
            cfg = {"schema":"SAME-K/1", "sink":sink, "sink_public":public(sink_key), "issuer_public":issuer_public, "controller":controller, "policy":POLICY, "epoch":"1"}
            db.executemany("INSERT INTO meta VALUES(?,?)", cfg.items())
            db.execute("INSERT INTO resources VALUES(?,?,?)", (target,value,version))
        return cls(p,sink_key)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path.as_uri()+"?mode=rw", uri=True, timeout=5)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def controller(self, actor):
        need(actor == self.meta["controller"], "CONTROL_ROLE")

    def operation(self, db, k, h):
        kt = key_text(k)
        need(k["sink"] == self.meta["sink"], "SINK_BINDING")
        row = db.execute("SELECT content,h,state,result FROM operations WHERE k=?", (kt,)).fetchone()
        need(row is not None, "UNKNOWN_K")
        need(row[1] == h, "CONTENT_CONFLICT")
        return kt,row

    @staticmethod
    def latest(db, kt):
        return db.execute("SELECT g,attempt_id,subject,state FROM attempts WHERE k=? ORDER BY g DESC LIMIT 1", (kt,)).fetchone()

    @staticmethod
    def event(db, kind, kt, data):
        db.execute("INSERT INTO events(kind,k,data) VALUES(?,?,?)", (kind,kt,canonical(data).decode()))

    def bind(self, k, content, *, actor):
        self.controller(actor)
        kt,h = key_text(k),content_hash(content)
        need(k["sink"] == self.meta["sink"], "SINK_BINDING")
        with self.transaction() as db:
            row = db.execute("SELECT content,h FROM operations WHERE k=?", (kt,)).fetchone()
            if row:
                need(row == (canonical(content).decode(),h), "CONTENT_CONFLICT")
            else:
                db.execute("INSERT INTO operations VALUES(?,?,?,'BOUND',NULL)", (kt,canonical(content).decode(),h))
                self.event(db,"BUSINESS_BOUND",kt,{"content_hash":h})
        return h

    def assign(self, k, h, expected_generation, subject, request_id, *, actor):
        self.controller(actor)
        need(type(expected_generation) is int and expected_generation >= 0 and text_field(subject) and text_field(request_id), "ASSIGN_FIELDS")
        params = canonical([k,h,expected_generation,subject]).decode()
        with self.transaction() as db:
            kt,row = self.operation(db,k,h)
            old = db.execute("SELECT parameters,g FROM allocations WHERE request_id=?", (request_id,)).fetchone()
            if old:
                need(old[0] == params, "ALLOCATION_ID_CONFLICT")
            need(row[2] != "DONE", "RESULT_ALREADY_COMMITTED")
            current = self.latest(db,kt)
            if old:
                need(current is not None and current[0] == old[1] and current[2] == subject and current[3] == "OPEN", "STALE_ALLOCATION")
            else:
                need((current[0] if current else 0) == expected_generation, "GENERATION_CONFLICT")
                need(current is None or current[3] == "FENCED", "ATTEMPT_STILL_OPEN")
                current = (expected_generation+1,uuid.uuid4().hex,subject,"OPEN")
                db.execute("INSERT INTO attempts VALUES(?,?,?,?,'OPEN')", (kt,*current[:3]))
                db.execute("INSERT INTO allocations VALUES(?,?,?,?)", (request_id,params,kt,current[0]))
                db.execute("INSERT OR IGNORE INTO readers VALUES(?,?)", (kt,subject))
                self.event(db,"ATTEMPT_ASSIGNED",kt,{"generation":current[0],"subject":subject,"attempt_id":current[1]})
            body = dict(action="ALLOCATED", key=k, content_hash=h, generation=current[0], attempt_id=current[1], subject=subject, policy=self.meta["policy"], epoch=int(self.meta["epoch"]), sink_public=self.meta["sink_public"], issuer_public=self.meta["issuer_public"])
            self.fault("before_assignment_commit")
        self.fault("after_assignment_commit")
        return signed(self.key,ALLOCATION_DOMAIN,body)

    def grant_read(self, k, h, subject, *, actor):
        self.controller(actor)
        need(text_field(subject), "SUBJECT")
        with self.transaction() as db:
            kt,_ = self.operation(db,k,h)
            db.execute("INSERT OR IGNORE INTO readers VALUES(?,?)", (kt,subject))
            self.event(db,"READ_AUTHORIZED",kt,{"subject":subject})

    def result(self, db, kt, row):
        found = db.execute("SELECT result FROM effects WHERE k=?", (kt,)).fetchone()
        if row[2] == "DONE":
            need(found is not None and row[3] == found[0], "RESULT_INCONSISTENT")
            envelope = json.loads(found[0])
            b = verify(envelope,self.meta["sink_public"],RESULT_DOMAIN)
            need(key_text(b["key"]) == kt and b["content_hash"] == row[1], "RESULT_BINDING")
            return envelope
        need(found is None and row[3] is None, "RESULT_INCONSISTENT")
        return None

    def read_result(self, k, h, *, actor):
        with self.transaction() as db:
            kt,row = self.operation(db,k,h)
            need(actor == self.meta["controller"] or db.execute("SELECT 1 FROM readers WHERE k=? AND subject=?", (kt,actor)).fetchone(), "READ_ROLE")
            result = self.result(db,kt,row)
            need(result is not None, "RESULT_NOT_AVAILABLE")
            return result

    def resolve(self, k, h, generation, attempt_id, challenge, *, actor):
        self.controller(actor)
        need(type(generation) is int and text_field(attempt_id) and text_field(challenge), "RESOLVE_FIELDS")
        with self.transaction() as db:
            kt,row = self.operation(db,k,h)
            current = self.latest(db,kt)
            need(current is not None and current[:2] == (generation,attempt_id), "STALE_ATTEMPT")
            result = self.result(db,kt,row)
            if result is not None:
                need(current[3] == "APPLIED", "ATTEMPT_INCONSISTENT")
                disposition = "RESULT_RETRIEVED"
            else:
                need(current[3] in ("OPEN","FENCED"), "APPLIED_RESULT_MISSING")
                db.execute("UPDATE attempts SET state='FENCED' WHERE k=? AND g=?", (kt,generation))
                disposition = "NONEXECUTION_FENCED"
            self.event(db,"ATTEMPT_RESOLVED",kt,{"generation":generation,"disposition":disposition})
            body = dict(action="RESOLVED", key=k, content_hash=h, generation=generation, attempt_id=attempt_id, challenge=challenge, disposition=disposition, result=result, sink_public=self.meta["sink_public"])
            self.fault("before_fence_commit")
        self.fault("after_fence_commit")
        return signed(self.key,RESOLUTION_DOMAIN,body)

    def execute(self, permit, content, *, actor):
        b = verify(permit,self.meta["issuer_public"],PERMIT_DOMAIN)
        fields = ("action","key","content_hash","generation","attempt_id","subject","policy","epoch","sink_public","issuer_public","schema","not_before","not_after")
        shape(b,fields)
        need(b["schema"] == "PERMIT/2" and b["action"] == "EXECUTE", "PERMIT_SCHEMA")
        need(text_field(actor) and actor == b["subject"], "SUBJECT_BINDING")
        need(b["sink_public"] == self.meta["sink_public"] and b["issuer_public"] == self.meta["issuer_public"] and b["policy"] == self.meta["policy"], "CONTEXT_BINDING")
        need(type(b["epoch"]) is int and b["epoch"] == int(self.meta["epoch"]), "EPOCH_BINDING")
        now = self.clock()
        need(type(now) is int and type(b["not_before"]) is int and type(b["not_after"]) is int and b["not_before"] <= now < b["not_after"] <= b["not_before"]+300, "EXPIRED")
        need(type(b["generation"]) is int and b["generation"] > 0 and text_field(b["attempt_id"]), "ATTEMPT_FIELDS")
        h = content_hash(content)
        need(h == b["content_hash"], "CONTENT_CONFLICT")
        with self.transaction() as db:
            kt,row = self.operation(db,b["key"],h)
            need(row[0] == canonical(content).decode(), "CONTENT_CONFLICT")
            current = self.latest(db,kt)
            need(current is not None and current[:3] == (b["generation"],b["attempt_id"],actor), "STALE_ATTEMPT")
            need(current[3] in ("OPEN","APPLIED"), "OLD_CONTINUATION_FENCED")
            result = self.result(db,kt,row)
            if result is not None:
                need(current[3] == "APPLIED", "ATTEMPT_INCONSISTENT")
                return {"status":"RECOVERED", "result":result}
            need(current[3] == "OPEN", "APPLIED_RESULT_MISSING")
            resource = db.execute("SELECT value,version FROM resources WHERE target=?", (content["target"],)).fetchone()
            need(resource is not None and resource[1] == content["expected_version"], "SQL_PRECONDITION")
            result = signed(self.key,RESULT_DOMAIN,dict(action="SQL_SET_COMMITTED", key=b["key"], content_hash=h, generation=current[0], subject=actor, effect_id=uuid.uuid4().hex, target=content["target"], old_value=resource[0], value=content["value"], old_version=resource[1], new_version=resource[1]+1, sink_public=self.meta["sink_public"]))
            raw = canonical(result).decode()
            db.execute("UPDATE resources SET value=?,version=version+1 WHERE target=?", (content["value"],content["target"]))
            db.execute("INSERT INTO effects VALUES(?,?,?)", (kt,result["body"]["effect_id"],raw))
            db.execute("UPDATE operations SET state='DONE',result=? WHERE k=?", (raw,kt))
            db.execute("UPDATE attempts SET state='APPLIED' WHERE k=? AND g=?", (kt,current[0]))
            self.event(db,"EFFECT_COMMITTED",kt,{"effect_id":result["body"]["effect_id"],"generation":current[0]})
            self.fault("before_effect_commit")
        self.fault("after_effect_commit")
        return {"status":"NEW", "result":result}

    def snapshot(self):
        """Read-only lab evidence; no private signing material is exported."""
        with self.transaction() as db:
            return {name:[list(r) for r in db.execute("SELECT * FROM "+name+" ORDER BY 1")] for name in ("meta","resources","operations","attempts","allocations","readers","effects","events")}
