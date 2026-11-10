"""Linux AF_UNIX data-only façade around the preserved LIFE01 fixture.

The service UID and the host administrator are trusted. Separate unprivileged
client UIDs cannot choose dependencies, attach workers or open protected state.
The spend ledger must survive consumer restoration. C004 remains open.
"""
from dataclasses import asdict
import fcntl
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import struct
import time

from . import VERSION
from .observation import Observation
from .policy import verify_policy
from .strict_json import InputError, MAX_BYTES, canonical, integer, loads, shape
from .vendor import DispatchAuthority, SQLiteSinkAnchor
from .finalizing_consumer import FinalizingConsumer
from .spend_ledger import SpendLedger

CONTEXT = "C02-SOFTWARE-FIXTURE/1"
KEY_NAMES = ("state", "rearm", "anchor", "token", "receipt", "effect", "local_rearm", "spend")
ROLE_OPS = {
    "requester": {"status", "evaluate", "prepare", "deliver", "finish", "inspect"},
    "maintainer": {"status", "evaluate", "rearm_state", "rearm_authority", "rearm_local",
                   "cancel", "fixture_observe", "inspect"},
}


def protected_dir(path, mode):
    s = Path(path).lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != mode:
        raise ValueError("directory ownership/mode")


def protected_file(path, *, metadata_only=False):
    # O_NOFOLLOW, fstat and link count protect the actual opened file.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid()
                or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1
                or (not metadata_only and s.st_size > MAX_BYTES)):
            raise ValueError("file ownership/mode/size")
        if metadata_only:
            return b""
        with os.fdopen(fd, "rb", closefd=False) as f:
            return f.read(MAX_BYTES + 1)
    finally:
        os.close(fd)


def request_id(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise InputError("request id")
    return value


def clock():
    # One LIFE01 logical tick = one monotonic second in this software fixture.
    return time.monotonic_ns() // 1_000_000_000


class Service:
    def __init__(self, runtime):
        if os.geteuid() == 0:
            raise ValueError("service must use a dedicated non-root UID")
        self.runtime = Path(runtime)
        protected_dir(self.runtime, 0o700)
        cfg = shape(loads(protected_file(self.runtime / "deployment.json")),
                    ("schema", "service_uid", "requester_uid", "maintainer_uid", "socket_dir"))
        if cfg["schema"] != "FCI-C02-DEPLOY/1":
            raise ValueError("deployment schema")
        uids = [integer(cfg[k], 1, 2**31-1) for k in ("service_uid", "requester_uid", "maintainer_uid")]
        if len(set(uids)) != 3 or cfg["service_uid"] != os.geteuid():
            raise ValueError("distinct UIDs")
        self.roles = {cfg["requester_uid"]: "requester", cfg["maintainer_uid"]: "maintainer"}
        self.socket_dir = Path(cfg["socket_dir"])
        protected_dir(self.socket_dir, 0o755)
        self.socket_path = self.socket_dir / "fci.sock"
        if len(os.fsencode(self.socket_path)) > 100:
            raise ValueError("Unix socket path length")
        # An exclusive service lifetime lock prevents live internal attachments.
        self.lock_fd = os.open(self.runtime / "service.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        s = os.fstat(self.lock_fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1:
            raise ValueError("lock metadata")
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.policy = verify_policy(protected_file(self.runtime / "policy.json"),
                                    protected_file(self.runtime / "policy-public.key"))
        self._open_state()

    def _open_state(self):
        """Trusted startup only; also exercised by the explicitly in-process tests."""
        keys = shape(loads(protected_file(self.runtime / "keys.json")), KEY_NAMES)
        if any(type(v) is not str or not re.fullmatch(r"[0-9a-f]{64}", v) for v in keys.values()):
            raise ValueError("key encoding")
        k = {n: bytes.fromhex(v) for n, v in keys.items()}
        if len(set(k.values())) != len(KEY_NAMES):
            raise ValueError("distinct keys")
        # Existing stores only: missing or corrupt state never silently resets.
        for filename in ("anchor.db", "replica.db", "consumer.db", "spend.db"):
            protected_file(self.runtime / filename, metadata_only=True)
        self.anchor = SQLiteSinkAnchor(self.runtime / "anchor.db", k["anchor"], "I", k["token"], k["receipt"])
        self.authority = DispatchAuthority(self.runtime / "replica.db", k["state"], k["rearm"], "I", self.anchor)
        # No _startup switch is exposed or used. Every opening records STARTUP.
        self.spend = SpendLedger(self.runtime / "spend.db", k["spend"],
                                 {"instance": "I", "target": "SIM_SINK", "policy": self.policy.digest, "context": CONTEXT})
        self.consumer = FinalizingConsumer(self.runtime / "consumer.db", k["effect"], k["token"], k["receipt"], k["local_rearm"], ledger=self.spend)
        a, c = self.authority.state(), self.consumer._state()
        if (a.policy, a.context, c.policy, c.context) != (self.policy.digest, CONTEXT, self.policy.digest, CONTEXT):
            raise ValueError("policy/state binding; explicit migration required")
        self.observation = Observation(self.policy)
        self.conditions = tuple(self.policy.body["fixture"]["conditions"])
        self.levels = self.policy.body["action_levels"]
        self.poisoned = False

    def _flags(self, action=None):
        flags = list(self.conditions)
        if action is not None:
            d = self.observation.decide()
            flags[4] = flags[4] and d.model_authorized and action in d.common_actions
        return tuple(flags)

    @staticmethod
    def _result(r):
        return {"code": r.code, "new_effect": bool(getattr(r, "new_effect", False))}

    def handle(self, uid, raw):
        role = self.roles.get(uid)
        if role is None:
            return {"code": "BLOCK_ROLE"}
        if self.poisoned:
            return {"code": "BLOCK_SERVICE_FAULT"}
        try:
            req = loads(raw)
            if type(req) is not dict or type(req.get("op")) is not str:
                raise InputError("operation")
            op = req["op"]
            if op not in ROLE_OPS[role]:
                return {"code": "BLOCK_ROLE"}
            if op in ("status", "evaluate", "rearm_state"):
                shape(req, ("op",))
            elif op == "prepare":
                shape(req, ("op", "request_id", "action"))
                request_id(req["request_id"])
                if type(req["action"]) is not str or req["action"] not in self.levels:
                    raise InputError("action")
            elif op in ("deliver", "cancel"):
                shape(req, ("op", "ticket"))
            elif op in ("finish", "inspect"):
                shape(req, ("op", "request_id"))
                request_id(req["request_id"])
            elif op in ("rearm_authority", "rearm_local"):
                shape(req, ("op", "witness"))
            elif op == "fixture_observe":
                shape(req, ("op", "conditions"))
                f = req["conditions"]
                if type(f) is not list or len(f) != 5 or any(type(x) is not bool for x in f):
                    raise InputError("exact boolean conditions")
        except (InputError, ValueError, TypeError):
            return {"code": "BLOCK_INPUT"}
        try:
            return self._dispatch(op, req)
        except Exception:
            # A side effect may already have committed. No optimistic retry and
            # no exception text or key material goes back to the client.
            self.poisoned = True
            return {"code": "OUTCOME_UNKNOWN_SERVICE_FAULT"}

    def _dispatch(self, op, req):
        if op == "status":
            a, c = self.authority.state(), self.consumer._state()
            return {"code": "STATUS", "candidate": VERSION, "policy": self.policy.digest,
                    "authority_mask": a.mask, "consumer_mask": c.mask, "level": c.level,
                    "mode": "SOFTWARE_FIXTURE", "nonleak_end_to_end": False}
        if op == "evaluate":
            d = self.observation.decide()
            return {"code": d.verdict, "action": d.action, "reason": d.reason,
                    "common_actions": sorted(d.common_actions), "policy": self.policy.digest,
                    "physical_effect": False}
        if op == "rearm_state":
            return {"code": "REARM_STATE", "authority": asdict(self.authority.state()),
                    "consumer": asdict(self.consumer._state()), "now": clock()}
        if op == "fixture_observe":
            self.conditions = tuple(req["conditions"])
            return self._result(self.authority.observe(self.conditions))
        if op == "rearm_authority":
            return self._result(self.authority.rearm(self._flags(), req["witness"], clock()))
        if op == "rearm_local":
            return self._result(self.consumer.rearm(self._flags(), req["witness"], self.anchor, clock()))
        if op == "prepare":
            action = req["action"]
            flags = self._flags(action)
            act = {"op": "set_level", "value": self.levels[action]}
            issued = self.authority.issue(flags, act, req["request_id"], clock())
            if issued.code != "TOKEN_ISSUED":
                return self._result(issued)
            accepted = self.authority.consume(self._flags(action), issued.token, act, clock())
            if not accepted.new_record:
                # A historical receipt is not a new authorization or ticket.
                return self._result(accepted)
            return {"code": accepted.code, "ticket": {"token": issued.token, "receipt": accepted.receipt}}
        if op == "deliver":
            return self._result(self.consumer.receive(req["ticket"], self.anchor, clock()))
        if op == "cancel":
            return self._result(self.consumer.cancel(req["ticket"], clock(), reason="USER_CANCEL"))
        if op == "inspect":
            entry = self.consumer._entry(req["request_id"])
            return {"code": "ENTRY", "status": entry["status"] if entry else "NONE"}
        if op == "finish":
            entry = self.consumer._entry(req["request_id"])
            if entry is None or entry["status"] != "PENDING":
                return self._result(self.consumer.finish(req["request_id"], self.anchor, clock, self._flags))
            level = entry["ticket"]["token"]["body"]["action"]["value"]
            action = next((name for name, v in self.levels.items() if v == level), None)
            if action is None:
                return {"code": "BLOCK_ACTION"}
            return self._result(self.consumer.finish(req["request_id"], self.anchor, clock,
                                                     lambda: self._flags(action)))
        raise AssertionError("unreachable operation")

    def serve(self):
        if self.socket_path.exists() or self.socket_path.is_symlink():
            s = self.socket_path.lstat()
            if not stat.S_ISSOCK(s.st_mode) or s.st_uid != os.geteuid():
                raise ValueError("unexpected socket path")
            self.socket_path.unlink()  # exclusive lifetime lock already held
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o666)
        listener.listen(16)
        print("READY " + VERSION, flush=True)
        try:
            while True:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(1.0)
                    try:
                        _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        # One request per connection, 4-byte big-endian length.
                        header = recv_exact(conn, 4)
                        length = struct.unpack("!I", header)[0]
                        if not 0 < length <= MAX_BYTES:
                            response = {"code": "BLOCK_INPUT"}
                        else:
                            response = self.handle(uid, recv_exact(conn, length))
                        encoded = canonical(response)
                        conn.sendall(struct.pack("!I", len(encoded)) + encoded)
                    except (OSError, EOFError, InputError):
                        pass
        finally:
            listener.close()
            self.consumer.close()
            self.spend.close()
            self.authority.close()
            self.anchor.close()
            os.close(self.lock_fd)


def recv_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("short frame")
        data.extend(chunk)
    return bytes(data)
