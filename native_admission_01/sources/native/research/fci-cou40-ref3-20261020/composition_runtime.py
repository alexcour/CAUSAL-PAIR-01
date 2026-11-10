"""REF3 research composition of byte-frozen LIFE01 and RC3 components.

This module is not the production Service and adds no actuator, root of trust,
or policy migration. INPUT_INVALID is a typed input diagnostic projected onto
the five existing fault bits (31). The stored mask cannot distinguish it from
five genuine faults. Actual LIFE01 observed/rearm and RC3 _finalize implement
the transitions; no Python copy of the Lean classifier is used.

An additional trusted check may replace a fence created inside this very
uncommitted finish transaction. Durable fences and historical requests are
never replaced. A later failure is handled by the existing RC3 finalizer and
its ordinary commit: level withdrawn, pending entry ineligible, fault bits
retained and independent per-ID reservation retained. Further checks are not
sampled after a denial. No claim covers changes after the final sampled check.
"""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import sys
from typing import Callable
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parent / "fci-c02-a04-20261018"
sys.path.insert(0, str(RUNTIME))

from fci_hardened.finalizing_consumer import FinalizingConsumer
from fci_hardened.spend_ledger import ticket_digest
from fci_hardened.vendor import Consumer  # also resolves the frozen vendor imports
from lifecycle import HOLD, Result, failures, observed

VERSION = "FCI-COU40-REF3-COMPOSITION/1"
Flags = tuple[bool, bool, bool, bool, bool]
ALL_FAULTS: Flags = (False, False, False, False, False)


class InputDiagnostic(str, Enum):
    VALID = "VALID"
    INPUT_INVALID = "INPUT_INVALID"


@dataclass(frozen=True)
class Observation:
    flags: Flags
    diagnostic: InputDiagnostic = InputDiagnostic.VALID
    reason: str | None = None

    def __post_init__(self):
        failures(self.flags)  # exact tuple and exact bools, from frozen LIFE01
        if type(self.diagnostic) is not InputDiagnostic:
            raise TypeError("typed input diagnostic required")
        if self.diagnostic is InputDiagnostic.INPUT_INVALID and self.flags != ALL_FAULTS:
            raise ValueError("invalid input must conservatively set all five faults")

    @property
    def input_invalid(self):
        return self.diagnostic is InputDiagnostic.INPUT_INVALID


def encode_observation(raw: object) -> Observation:
    """Total ordinary flags boundary. This function alone stores no observation."""
    if type(raw) is not tuple:
        return Observation(ALL_FAULTS, InputDiagnostic.INPUT_INVALID, "FLAGS_TUPLE")
    if len(raw) != 5:
        return Observation(ALL_FAULTS, InputDiagnostic.INPUT_INVALID, "FLAGS_COUNT")
    if any(type(flag) is not bool for flag in raw):
        return Observation(ALL_FAULTS, InputDiagnostic.INPUT_INVALID, "FLAGS_BOOL")
    return Observation(raw)


@dataclass(frozen=True)
class Recheck:
    """Trusted internal providers; never decoded from an IPC client request."""
    name: str
    clock: Callable[[], int]
    conditions: Callable[[], object]

    def __post_init__(self):
        if type(self.name) is not str or not self.name or len(self.name) > 64:
            raise ValueError("check name")
        if not callable(self.clock) or not callable(self.conditions):
            raise TypeError("trusted check providers required")


class CompositionConsumer(FinalizingConsumer):
    """A separate sequential research entrypoint using the original SQL stores.

    The _startup argument retains the vendor meaning: false is only a live
    fixture attachment, never a restart. Rearm, scope and history are inherited.
    A terminal finish does not sample providers; ACK_REARM_HISTORY similarly
    does not introduce a new observation. Use observe for an explicit new one.
    """
    def __init__(self, *args, **kwargs):
        self._composition_active = None
        self._composition_trace = {}
        super().__init__(*args, **kwargs)

    @property
    def last_trace(self):
        return copy.deepcopy(self._composition_trace)

    def observe(self, raw: object, now: int):
        observation = encode_observation(raw)
        def transition(_point):
            state = observed(self._state(), observation.flags, now)
            self._write_state(state)
            code = ("BLOCK_INPUT_INVALID" if observation.input_invalid else
                    "BLOCK_LOCAL_LATCHED" if state.mask else "LOCAL_OBSERVATION_RECORDED")
            return Result(code, state)
        return self._transaction("ref3_observe", transition)

    def _normalizer(self, provider, label):
        def read():
            observation = encode_observation(provider())
            self._composition_trace["observations"].append({
                "point": label, "flags": list(observation.flags),
                "diagnostic": observation.diagnostic.value, "reason": observation.reason})
            return observation.flags
        return read

    def finish(self, rid, anchor, clock, conditions, hook=None, *, rechecks=()):
        if self._composition_active is not None:
            raise RuntimeError("reentrant composition finish is outside this entrypoint")
        if type(rechecks) is not tuple or any(type(check) is not Recheck for check in rechecks):
            raise TypeError("an exact tuple of typed Recheck providers is required")
        entry = self._entry(rid)
        self._composition_trace = {
            "version": VERSION, "request_id": rid, "observations": [],
            "finalizers": [], "removed_uncommitted_fences": [], "skipped_checks": []}
        self._composition_active = {
            "rid": rid, "ticket_digest": ticket_digest(entry["ticket"]) if entry else None,
            "rechecks": rechecks, "owned_fence": None,
        }
        try:
            result = super().finish(rid, anchor, clock,
                                    self._normalizer(conditions, "initial_finish"), hook)
            self._composition_trace["response"] = {"code": result.code, "new_effect": result.new_effect}
            return result
        except Exception as exc:
            self._composition_trace["exception"] = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            self._composition_trace["in_transaction_after_return"] = self.db.in_transaction
            self._composition_active = None

    def _raw_fence(self, rid):
        return self.db.execute("SELECT payload,signature FROM commit_fence WHERE request_id=?", (rid,)).fetchone()

    def _run_original_finalizer(self, index, rid, before, original, anchor, clock, conditions):
        """Capture inputs consumed by the real method, not a reconstructed verdict."""
        staged = self._state()
        ticket = self._entry(rid)["ticket"]
        token, receipt = ticket["token"]["body"], ticket["receipt"]["body"]
        samples, observed_flags, sources = [], [], []
        source_method = self._source
        def sample_clock():
            value = clock(); samples.append(value); return value
        def sample_conditions():
            value = conditions(); observed_flags.append(value); return value
        def sample_source(a, t):
            value = source_method(a, t); sources.append(value); return value
        with patch.object(self, "_source", side_effect=sample_source):
            verdict = super()._finalize(rid, before, original, anchor, sample_clock, sample_conditions)
        if (len(samples), len(observed_flags), len(sources)) != (2, 1, 1):
            raise RuntimeError("unexpected frozen finalizer call structure")
        first, last = samples
        good, source = sources[0]
        scope_ok = ((staged.instance, staged.target, staged.policy, staged.context)
                    == (before.instance, before.target, before.policy, before.context)
                    and staged.policy == self.ledger.scope["policy"]
                    and staged.context == self.ledger.scope["context"]
                    and staged.level == receipt["action"]["value"])
        guard = {"previous": staged.last_time, "first": first, "last": last,
                 "mask": failures(observed_flags[0]), "oldMask": staged.mask,
                 "sourceOk": good, "sourceRevision": source.revision if source is not None else 0,
                 "floor": staged.authority_floor, "accepted": receipt["accepted_at"],
                 "expiry": token["expires_at"], "hold": HOLD, "scopeOk": scope_ok}
        row = self._raw_fence(rid)
        fence = self._fence(rid)  # authenticate the row just written by RC3
        active = self._composition_active
        if (not self.db.in_transaction or fence["ticket_digest"] != active["ticket_digest"]
                or fence["request_id"] != rid or fence["consumer_revision"] != staged.revision):
            raise RuntimeError("new fence is not owned by this finish transaction")
        active["owned_fence"] = row
        self._composition_trace["finalizers"].append({
            "index": index, "operation": "late_fence", "before": asdict(staged),
            "input": {"guard": guard, "rollback_level": before.level},
            "after_attested": asdict(self._state()), "code": verdict,
            "durability": "STAGED_UNCOMMITTED", "fence": fence,
            "raw_fence": {"payload_utf8": row[0].decode(), "signature": row[1]},
            "in_transaction": self.db.in_transaction, "superseded_before_commit": False,
        })
        return verdict

    def _replace_owned_fence(self, rid):
        active = self._composition_active
        if active is None or active["rid"] != rid or not self.db.in_transaction:
            raise RuntimeError("no active uncommitted finish owns this fence")
        expected = active["owned_fence"]
        actual = self._raw_fence(rid)
        fence = self._fence(rid)  # signature and schema checked again before deletion
        if (expected is None or actual != expected or fence is None
                or fence["decision"] != "COMMIT_FENCE_PASS"
                or fence["ticket_digest"] != active["ticket_digest"]
                or self._entry(rid)["status"] != "DONE"):
            raise RuntimeError("only this transaction's fresh PASS fence can be replaced")
        cursor = self.db.execute(
            "DELETE FROM commit_fence WHERE request_id=? AND payload=? AND signature=?",
            (rid, expected[0], expected[1]))
        if cursor.rowcount != 1:
            raise RuntimeError("fence ownership changed")
        self._composition_trace["removed_uncommitted_fences"].append(
            {"request_id": rid, "payload_utf8": expected[0].decode(), "signature": expected[1]})
        self._composition_trace["finalizers"][-1]["superseded_before_commit"] = True
        active["owned_fence"] = None

    def _finalize(self, rid, before, original, anchor, clock, conditions):
        active = self._composition_active
        if active is None or active["rid"] != rid or not self.db.in_transaction:
            raise RuntimeError("finalization requires the normal active finish transaction")
        if self._raw_fence(rid) is not None:
            raise RuntimeError("a pre-existing fence must never be replaced")
        verdict = self._run_original_finalizer(0, rid, before, original, anchor, clock, conditions)
        for index, check in enumerate(active["rechecks"], start=1):
            if verdict != "COMMIT_FENCE_PASS":
                self._composition_trace["skipped_checks"] = [c.name for c in active["rechecks"][index-1:]]
                break
            self._replace_owned_fence(rid)
            verdict = self._run_original_finalizer(
                index, rid, before, original, anchor, check.clock,
                self._normalizer(check.conditions, check.name))
        return verdict


def source_identities():
    sources = [RUNTIME / "fci_hardened/finalizing_consumer.py",
               RUNTIME / "fci_hardened/guarded_consumer.py",
               RUNTIME / "vendor/fci_repair05_life01/lifecycle.py"]
    return {str(path.relative_to(HERE.parent)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources}
