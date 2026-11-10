"""Private research prototype. Nominal authority only; no actuator driver.

The external verifier attests semantic repairs; HMAC authenticates and binds
that attestation, it does not establish the physical validity of any repair.
Storage and clock assumptions are stated in protocol.json.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Callable
from urllib.parse import quote

CAUSES = ("runtime", "proof", "history", "contract", "observer", "startup", "scope")
KINDS = ("runtime_envelope", "proof_validation", "history_reconciliation",
         "contract_calibration", "observer_validation", "commissioning", "policy_context_validation")
STARTUP, SCOPE = 32, 64
MAX_TTL = 60


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def mac(key: bytes, domain: bytes, value: object) -> str:
    return hmac.new(key, domain + canonical(value), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class State:
    instance: str
    policy: str
    context: str
    mask: int
    epoch: int
    revision: int

    def validate(self) -> None:
        if any(type(v) is not str or not v or len(v) > 256
               for v in (self.instance, self.policy, self.context)):
            raise ValueError("invalid identity or scope")
        if any(type(v) is not int or v < 0 for v in (self.mask, self.epoch, self.revision)):
            raise ValueError("invalid counters")
        if self.mask > 127:
            raise ValueError("unknown cause")


@dataclass(frozen=True)
class Decision:
    code: str
    state: State | None

    @property
    def nominal_allowed(self) -> bool:
        return self.code == "ALLOW_NOMINAL"


def failures(flags: tuple[bool, ...]) -> int:
    if type(flags) is not tuple or len(flags) != 5 or any(type(v) is not bool for v in flags):
        raise ValueError("five exact booleans required")
    return sum(1 << i for i, flag in enumerate(flags) if not flag)


def observe_step(state: State, flags: tuple[bool, ...]) -> Decision:
    state.validate()
    mask = state.mask | failures(flags)
    nxt = replace(state, mask=mask, epoch=state.epoch + int(mask != state.mask),
                  revision=state.revision + 1)
    return Decision("ALLOW_NOMINAL" if mask == 0 else "BLOCK_LATCHED", nxt)


def repair_claims(mask: int) -> list[dict[str, str]]:
    return [{"cause": CAUSES[i], "kind": KINDS[i], "proof_id": f"FIXTURE-{CAUSES[i]}"}
            for i in range(7) if mask & (1 << i)]


def fixture_witness(state: State, key: bytes, now: int, ttl: int = 10) -> dict:
    """Test issuer, deliberately NOT an industrial repair verifier."""
    body = {"schema": 1, "instance": state.instance, "policy": state.policy,
            "context": state.context, "epoch": state.epoch, "mask": state.mask,
            "action": "REARM_NOMINAL", "issued_at": now, "expires_at": now + ttl,
            "repairs": repair_claims(state.mask)}
    return {"body": body, "signature": mac(key, b"FCI-REPAIR-01/WITNESS\0", body)}


def valid_witness(state: State, witness: object, key: bytes, now: int) -> bool:
    if type(now) is not int or now < 0 or type(witness) is not dict:
        return False
    if set(witness) != {"body", "signature"}:
        return False
    body, sig = witness["body"], witness["signature"]
    required = {"schema", "instance", "policy", "context", "epoch", "mask", "action",
                "issued_at", "expires_at", "repairs"}
    if type(body) is not dict or set(body) != required or type(sig) is not str:
        return False
    if any(type(body[k]) is not int for k in ("schema", "epoch", "mask", "issued_at", "expires_at")):
        return False
    if body["schema"] != 1 or any(body[k] != getattr(state, k)
                                  for k in ("instance", "policy", "context", "epoch", "mask")):
        return False
    if body["action"] != "REARM_NOMINAL":
        return False
    issued, expires = body["issued_at"], body["expires_at"]
    if not (0 <= issued <= now < expires and 0 < expires - issued <= MAX_TTL):
        return False
    repairs = body["repairs"]
    expected = [(CAUSES[i], KINDS[i]) for i in range(7) if state.mask & (1 << i)]
    if type(repairs) is not list or len(repairs) != len(expected):
        return False
    for item, (cause, kind) in zip(repairs, expected):
        if type(item) is not dict or set(item) != {"cause", "kind", "proof_id"}:
            return False
        if item["cause"] != cause or item["kind"] != kind:
            return False
        if type(item["proof_id"]) is not str or not item["proof_id"]:
            return False
    try:
        return hmac.compare_digest(sig, mac(key, b"FCI-REPAIR-01/WITNESS\0", body))
    except (TypeError, ValueError, OverflowError):
        return False


def rearm_step(state: State, flags: tuple[bool, ...], witness: object,
               key: bytes, now: int) -> Decision:
    obs = observe_step(state, flags)
    nxt = obs.state
    assert nxt is not None
    if failures(flags):
        return Decision("BLOCK_REARM_CONDITIONS", nxt)
    if nxt.mask == 0:
        return Decision("BLOCK_NOT_LOCKED", nxt)
    if not valid_witness(nxt, witness, key, now):
        return Decision("BLOCK_REARM_WITNESS", nxt)
    return Decision("REARM_ACCEPTED", replace(nxt, mask=0, epoch=nxt.epoch + 1))


def scope_step(state: State, policy: str, context: str) -> Decision:
    nxt = replace(state, policy=policy, context=context, revision=state.revision + 1)
    if (policy, context) != (state.policy, state.context):
        nxt = replace(nxt, mask=state.mask | SCOPE, epoch=state.epoch + 1)
    nxt.validate()
    return Decision("SCOPE_RECORDED", nxt)


class StorageError(RuntimeError):
    pass


class Authority:
    """One long-lived handle per service; reopening requires commissioning.

    Key provisioning, accurate observations, trusted time and anti-rollback
    storage beyond an authenticated snapshot are external obligations.
    """
    def __init__(self, path: str | Path, state_key: bytes, rearm_key: bytes, instance: str):
        if len(state_key) < 32 or len(rearm_key) < 32 or state_key == rearm_key:
            raise ValueError("distinct keys of at least 32 bytes required")
        self.state_key, self.rearm_key, self.instance = state_key, rearm_key, instance
        try:
            uri = "file:" + quote(str(Path(path).resolve()), safe="/") + "?mode=rw"
            self.db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=10)
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("BEGIN IMMEDIATE")
            state = self._read()
            self._write(replace(state, mask=state.mask | STARTUP,
                                epoch=state.epoch + 1, revision=state.revision + 1))
            self.db.execute("COMMIT")
        except (sqlite3.Error, ValueError, TypeError, KeyError) as exc:
            if hasattr(self, "db"):
                self.db.close()
            raise StorageError("unavailable or unauthenticated authority state") from exc

    @classmethod
    def bootstrap(cls, path: str | Path, state_key: bytes, rearm_key: bytes,
                  instance: str, policy: str, context: str) -> "Authority":
        initial = State(instance, policy, context, STARTUP, 0, 0)
        initial.validate()
        if len(state_key) < 32 or len(rearm_key) < 32 or state_key == rearm_key:
            raise ValueError("distinct keys required")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE authority (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, signature TEXT NOT NULL)")
            db.execute("INSERT INTO authority VALUES(1,?,?)", (
                canonical(asdict(initial)).decode(), mac(state_key, b"FCI-REPAIR-01/STATE\0", asdict(initial))))
        return cls(path, state_key, rearm_key, instance)

    def _read(self) -> State:
        rows = self.db.execute("SELECT payload, signature FROM authority").fetchall()
        if len(rows) != 1:
            raise ValueError("exactly one state required")
        data, sig = json.loads(rows[0][0]), rows[0][1]
        if not hmac.compare_digest(sig, mac(self.state_key, b"FCI-REPAIR-01/STATE\0", data)):
            raise ValueError("state authentication failed")
        state = State(**data)
        state.validate()
        if state.instance != self.instance:
            raise ValueError("wrong service identity")
        return state

    def _write(self, state: State) -> None:
        state.validate()
        data = asdict(state)
        self.db.execute("UPDATE authority SET payload=?, signature=? WHERE id=1", (
            canonical(data).decode(), mac(self.state_key, b"FCI-REPAIR-01/STATE\0", data)))

    def _run(self, operation: Callable[[State], Decision]) -> Decision:
        try:
            self.db.execute("BEGIN IMMEDIATE")
            decision = operation(self._read())
            assert decision.state is not None
            self._write(decision.state)
            self.db.execute("COMMIT")
            return decision  # No nominal response before commit.
        except (sqlite3.Error, ValueError, TypeError, KeyError, OverflowError):
            try:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return Decision("BLOCK_STORAGE", None)

    def state(self) -> State:
        return self._read()

    def observe(self, flags: tuple[bool, ...], *, allow_degraded: bool = False) -> Decision:
        failures(flags)  # Invalid API arguments never yield an authorization.
        return self._run(lambda state: observe_step(state, flags))

    def rearm(self, flags: tuple[bool, ...], witness: object, now: int) -> Decision:
        failures(flags)
        return self._run(lambda state: rearm_step(state, flags, witness, self.rearm_key, now))

    def set_scope(self, policy: str, context: str) -> Decision:
        return self._run(lambda state: scope_step(state, policy, context))

    def close(self) -> None:
        self.db.close()
