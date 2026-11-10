"""FCI-OBS-IF/1 experimental boundary for the exact observer-v1 model.

Private research only. Model-authorized does not mean physically certified.
No RECOH decoder or general interval-clock observer is implemented here.
"""
from dataclasses import dataclass
from fractions import Fraction as Q
from types import MappingProxyType
from typing import Mapping

from observer import Observer, Packet, Region, stop_requirement


def exact(value):
    if type(value) is int or isinstance(value, Q):
        return Q(value)
    raise TypeError("exact integer or Fraction required")


def tick(value):
    return type(value) is int and value >= 0


@dataclass(frozen=True)
class Identity:
    schema: str
    model: str
    config: str
    boot: str
    clock: str
    units: tuple = ("m", "m/s")


@dataclass(frozen=True)
class Frame:
    identity: Identity
    source: str
    sequence: int
    capture_lower: int
    capture_upper: int
    arrival: int
    channel: str
    distance: Q
    velocity: Q | None = None
    diagnostic_valid: bool = True


@dataclass(frozen=True)
class Budgets:
    compute_queue: Q = Q(0)
    actuator: Q = Q(1, 100)
    hold: Q = Q(1, 100)
    deceleration: Q = Q(4, 5)
    coast_acceleration: Q = Q(1, 50)
    residual_distance: Q = Q(1, 5)

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, exact(getattr(self, name)))
        if min(self.compute_queue, self.actuator, self.hold,
               self.coast_acceleration, self.residual_distance) < 0 or self.deceleration <= 0:
            raise ValueError("invalid stopping/time contract")


@dataclass(frozen=True)
class Envelope:
    identity: Identity
    epoch: int
    valid_until: Q
    bank: Mapping[str, Region]
    last_capture: int | None
    inconsistent: bool
    dt: Q
    max_age: int
    revision: int = 0

    def __post_init__(self):
        object.__setattr__(self, "valid_until", exact(self.valid_until))
        object.__setattr__(self, "dt", exact(self.dt))
        object.__setattr__(self, "bank", MappingProxyType(dict(self.bank)))


@dataclass(frozen=True)
class Decision:
    verdict: str
    action: str
    reason: str
    common_actions: frozenset = frozenset()

    @property
    def model_authorized(self):
        return self.verdict == "PERMIT"


def fallback(reason):
    return Decision("FALLBACK_REQUEST", "BRAKE", reason)


class ObservationBoundary:
    """Rejects unsupported metadata without retroactive contraction of the bank.

    One declared source per channel, exact epoch only, session-wide replay keys.
    Once contradiction is observed, no automatic recovery is provided.
    """
    def __init__(self, observer: Observer, expected: Identity, sources=None, max_replay_entries=4096):
        self.observer = observer
        self.expected = expected
        self.sources = dict(sources or {"primary": "primary", "probe": "probe"})
        if not tick(max_replay_entries) or max_replay_entries == 0:
            raise ValueError("positive bounded replay capacity required")
        self.replay_capacity = max_replay_entries
        self.revision = 0
        self.seen = {(expected.boot, self.sources[p.channel], p.channel, p.sequence)
                     for events in observer.events.values() for p in events}
        if len(self.seen) > max_replay_entries:
            raise ValueError("existing replay history exceeds capacity")
        self.fault_latched = bool(observer.inconsistent)

    def receive(self, f: Frame):
        o = self.observer
        if f.identity != self.expected:
            return "IDENTITY_MISMATCH"
        if f.channel not in self.sources or f.source != self.sources[f.channel]:
            return "UNKNOWN_SOURCE"
        if not all(tick(v) for v in (f.sequence, f.capture_lower, f.capture_upper, f.arrival)):
            return "MALFORMED_TIME_OR_SEQUENCE"
        if f.capture_lower > f.capture_upper:
            return "INVERTED_CAPTURE_WINDOW"
        if f.capture_upper > f.arrival or f.arrival > o.epoch:
            return "FUTURE_OR_NONCAUSAL"
        if f.diagnostic_valid is not True:
            return "UNTRUSTED"
        if f.capture_lower != f.capture_upper:
            return "UNSUPPORTED_CAPTURE_INTERVAL"
        try:
            distance = exact(f.distance)
            velocity = None if f.velocity is None else exact(f.velocity)
        except TypeError:
            return "MALFORMED_MEASUREMENT"
        key = (f.identity.boot, f.source, f.channel, f.sequence)
        if key in self.seen:
            return "REPLAY"
        if self.fault_latched or o.inconsistent:
            return "FAULT_LATCHED"
        if len(self.seen) >= self.replay_capacity:
            return "REPLAY_LEDGER_FULL"
        # Physical truth, configured error bounds and correct timestamps are
        # assumptions; a diagnostic flag alone does not establish any of them.
        outcome = o.receive(Packet(f.capture_lower, f.sequence, f.channel,
                                   distance, velocity, f.diagnostic_valid))
        if outcome in ("APPLIED", "INCONSISTENT"):
            self.seen.add(key)
            self.revision += 1
        if outcome == "INCONSISTENT":
            self.fault_latched = True
        return outcome

    def snapshot(self, valid_until):
        o = self.observer
        return Envelope(self.expected, o.epoch, valid_until, o.bank,
                        o.last_capture, self.fault_latched or o.inconsistent, o.dt, o.max_age,
                        self.revision)

    def decide(self, envelope, budgets=Budgets()):
        """In-process authoritative entry point; rejects superseded snapshots.

        Serialized transport, concurrency and persistence are separate obligations.
        """
        o = self.observer
        if (envelope.revision != self.revision or envelope.epoch != o.epoch
                or dict(envelope.bank) != o.bank or envelope.last_capture != o.last_capture
                or envelope.dt != o.dt or envelope.max_age != o.max_age):
            return fallback("SUPERSEDED_OR_FOREIGN_ENVELOPE")
        return arbitrate(envelope, self.expected, o.epoch, budgets,
                         latched_fault=self.fault_latched or o.inconsistent)


def arbitrate(envelope: Envelope, expected: Identity, now_epoch: int,
              budgets=Budgets(), *, latched_fault=False):
    """Conservative stopping test on the CURRENT outer envelope.

    Parameter validity extends through the whole modeled backup stopping path.
    Enclosure soundness and dynamic inequalities are not proved for Python.
    """
    e = envelope
    if e.identity != expected:
        return fallback("IDENTITY_MISMATCH")
    if not tick(now_epoch) or not tick(e.epoch) or e.epoch != now_epoch:
        return fallback("EPOCH_MISMATCH")
    if latched_fault or e.inconsistent:
        return fallback("INCONSISTENT_LATCHED")
    if not tick(e.max_age) or e.dt <= 0:
        return fallback("INVALID_ENVELOPE_CONTRACT")
    if not e.bank or any(not r.vertices for r in e.bank.values()):
        return fallback("EMPTY_ENVELOPE")
    if not tick(e.last_capture) or e.last_capture > now_epoch or now_epoch-e.last_capture > e.max_age:
        return fallback("STALE_OR_NO_CAPTURE")
    dlo = min(r.bounds(0)[0] for r in e.bank.values())
    vlo = min(r.bounds(1)[0] for r in e.bank.values())
    vhi = max(r.bounds(1)[1] for r in e.bank.values())
    if vlo < 0:
        return fallback("OUTSIDE_FORWARD_MODEL")
    common = set()
    for action, extra in (("BRAKE", Q(0)), ("COAST", budgets.hold)):
        delay = budgets.compute_queue + budgets.actuator + extra
        stop_time = delay + (vhi+budgets.coast_acceleration*delay)/budgets.deceleration
        # This horizon covers the entire hypothetical stopping trajectory,
        # not merely emission of the current command.
        if now_epoch*e.dt + stop_time > e.valid_until:
            continue
        needed = stop_requirement(vhi, budgets.deceleration, delay,
                                  budgets.coast_acceleration, budgets.residual_distance)
        if dlo >= needed:
            common.add(action)
    if not common:
        return fallback("NO_COMMON_ACTION_IN_VALID_HORIZON")
    action = "COAST" if "COAST" in common else "BRAKE"
    return Decision("PERMIT", action, "CONDITIONAL_STOPPING_MODEL", frozenset(common))


def finite_reference(reading, noise, lower, upper):
    """Independent Python enumerator for the Lean temporal oracle.

    Discrete fixed-speed model only. A capture time is existential, not universal.
    """
    states = []
    for distance in range(7):
        for speed in range(2):
            for mode in range(2):
                possible = False
                for capture in range(lower, upper+1):
                    measured = distance+speed*(2-capture)+2*mode
                    if abs(measured-reading) <= noise:
                        possible = True
                if possible:
                    states.append((distance, speed, mode))
    brake = bool(states) and all(d >= 1+v for d, v, m in states)
    coast = bool(states) and all(d >= 1+2*v for d, v, m in states)
    return {"key": f"{reading}/{noise}/{lower}/{upper}",
            "candidates": [4*d+2*v+m for d, v, m in states],
            "coast": coast, "brake": brake,
            "verdict": "PERMIT_COAST" if coast else "PERMIT_BRAKE" if brake else "FALLBACK_REQUEST"}
