"""Exact rational planar set observer. Research model; no hardware interface.

Zonotopes initialize a bank of offset hypotheses. Linear prediction preserves
their generator correlations; measurement strips are intersected exactly as
convex polygons. A conservative box is used if standstill saturation is possible.
"""
from dataclasses import dataclass
from fractions import Fraction as Q
from itertools import product


def rational(value):
    if not isinstance(value, (int, Q)):
        raise TypeError("exact integer or Fraction required; no floating-point input")
    return Q(value)


def cross(o, a, b):
    return (a[0]-o[0])*(b[1]-o[1])-(a[1]-o[1])*(b[0]-o[0])


def hull(points):
    points = sorted(set(points))
    if len(points) < 2:
        return tuple(points)
    lower, upper = [], []
    for target, seq in ((lower, points), (upper, reversed(points))):
        for p in seq:
            while len(target) >= 2 and cross(target[-2], target[-1], p) <= 0:
                target.pop()
            target.append(p)
    return tuple(lower[:-1] + upper[:-1])


@dataclass(frozen=True)
class Region:
    vertices: tuple

    @staticmethod
    def convex(points):
        return Region(hull(tuple((rational(d), rational(v)) for d, v in points)))

    @staticmethod
    def box(d0, d1, v0, v1):
        if d0 > d1 or v0 > v1:
            return Region(())
        return Region.convex(product((d0, d1), (v0, v1)))

    @staticmethod
    def zonotope(center, generators):
        if len(generators) > 12:
            raise ValueError("enumerated zonotope initialization limited to 12 generators")
        return Region.convex((
            center[0]+sum(s*g[0] for s, g in zip(signs, generators)),
            center[1]+sum(s*g[1] for s, g in zip(signs, generators)))
            for signs in product((-1, 1), repeat=len(generators)))

    def contains(self, point):
        p = tuple(map(rational, point))
        if not self.vertices:
            return False
        if len(self.vertices) == 1:
            return p == self.vertices[0]
        if len(self.vertices) == 2:
            a, b = self.vertices
            return cross(a, b, p) == 0 and all(min(a[i], b[i]) <= p[i] <= max(a[i], b[i]) for i in (0, 1))
        return all(cross(a, b, p) >= 0 for a, b in zip(self.vertices, self.vertices[1:]+self.vertices[:1]))

    def subset(self, other):
        return all(other.contains(p) for p in self.vertices)

    def bounds(self, axis):
        if not self.vertices:
            raise ValueError("empty region has no finite envelope")
        values = [p[axis] for p in self.vertices]
        return min(values), max(values)

    def clip(self, normal, bound):
        """Closed halfspace n.x <= bound, including points and segments."""
        normal, bound = tuple(map(rational, normal)), rational(bound)
        if not self.vertices:
            return self
        out = []
        for a, b in zip(self.vertices, self.vertices[1:]+self.vertices[:1]):
            fa = sum(n*x for n, x in zip(normal, a))-bound
            fb = sum(n*x for n, x in zip(normal, b))-bound
            if fa <= 0:
                out.append(a)
            if fa*fb < 0:
                t = fa/(fa-fb)
                out.append(tuple(x+t*(y-x) for x, y in zip(a, b)))
        return Region.convex(out)

    def strip(self, axis, low, high):
        if low > high:
            return Region(())
        n = (Q(1), Q(0)) if axis == 0 else (Q(0), Q(1))
        return self.clip(n, high).clip(tuple(-x for x in n), -low)


def travel(v, a, t):
    v, a, t = map(rational, (v, a, t))
    if v < 0 or t < 0:
        raise ValueError("outside forward-motion model")
    moving = min(t, v/-a) if a < 0 else t
    return v*moving + a*moving*moving/2


def flow(state, a, t):
    d, v = map(rational, state)
    a, t = map(rational, (a, t))
    return d-travel(v, a, t), max(Q(0), v+a*t)


def predict(region, acceleration, t):
    """Outer reachable set at any t >= 0 for constant a in [alo, ahi]."""
    alo, ahi = map(rational, acceleration)
    t = rational(t)
    if t < 0 or alo > ahi:
        raise ValueError("invalid transition bounds")
    if not region.vertices:
        return region
    vlo, vhi = region.bounds(1)
    if vlo < 0:
        raise ValueError("negative velocity outside model")
    if vlo+alo*t >= 0:
        # Affine image + one shared acceleration generator; no box wrapping.
        return Region.convex((d-v*t-a*t*t/2, v+a*t)
                             for d, v in region.vertices for a in (alo, ahi))
    dlo, dhi = region.bounds(0)
    return Region.box(dlo-travel(vhi, ahi, t), dhi-travel(vlo, alo, t),
                      max(Q(0), vlo+alo*t), max(Q(0), vhi+ahi*t))


@dataclass(frozen=True)
class Packet:
    capture: int
    sequence: int
    channel: str
    distance: Q
    velocity: Q | None = None
    diagnostic_valid: bool = True

    def __post_init__(self):
        object.__setattr__(self, "distance", rational(self.distance))
        if self.velocity is not None:
            object.__setattr__(self, "velocity", rational(self.velocity))


class Observer:
    def __init__(self, initial_bank, offsets, *, dt=Q(1, 100), distance_noise=Q(1, 100),
                 speed_noise=Q(1, 50), probe_noise=Q(1, 200), history=8,
                 max_age=6, max_packets_per_epoch=8):
        if dt <= 0 or min(distance_noise, speed_noise, probe_noise) < 0:
            raise ValueError("invalid time or measurement bounds")
        if history < 0 or max_age < 0 or max_packets_per_epoch < 1 or not offsets:
            raise ValueError("invalid buffer/freshness contract")
        if set(initial_bank) != set(offsets) or any(not r.vertices or r.bounds(1)[0] < 0 for r in initial_bank.values()):
            raise ValueError("invalid initialized mode bank")
        self.dt, self.distance_noise, self.speed_noise = dt, distance_noise, speed_noise
        self.probe_noise, self.window, self.max_age = probe_noise, history, max_age
        self.capacity = max_packets_per_epoch
        self.offsets = dict(offsets)
        self.epoch = 0
        self.priors = {0: dict(initial_bank)}
        self.posts = {0: dict(initial_bank)}
        self.events = {0: []}
        self.transitions = {}
        self.last_capture = None
        self.inconsistent = False
        self.refinement_checks = 0

    @property
    def bank(self):
        return self.posts[self.epoch]

    @property
    def valid(self):
        return bool(self.bank) and not self.inconsistent and self.last_capture is not None and self.epoch-self.last_capture <= self.max_age

    def contains(self, state, mode=None):
        return any(r.contains(state) for key, r in self.bank.items() if mode is None or key == mode)

    def correct(self, bank, packet):
        out = {}
        for mode, region in bank.items():
            offset = self.offsets[mode] if packet.channel == "primary" else Q(0)
            noise = self.distance_noise if packet.channel == "primary" else self.probe_noise
            region = region.strip(0, packet.distance-offset-noise, packet.distance-offset+noise)
            if packet.velocity is not None:
                region = region.strip(1, max(Q(0), packet.velocity-self.speed_noise), packet.velocity+self.speed_noise)
            if region.vertices:
                out[mode] = region
        return out

    def receive(self, packet):
        if packet.channel not in ("primary", "probe") or not isinstance(packet.capture, int) or packet.capture < 0:
            return "MALFORMED"
        if not packet.diagnostic_valid:
            return "UNTRUSTED"
        if packet.capture > self.epoch:
            return "FUTURE"
        if packet.capture not in self.priors:
            return "TOO_OLD"
        events = self.events.setdefault(packet.capture, [])
        if any((p.sequence, p.channel) == (packet.sequence, packet.channel) for p in events):
            return "DUPLICATE"
        if len(events) >= self.capacity:
            return "CAPACITY"
        before = dict(self.bank)
        events.append(packet)
        # Correct the capture epoch, then replay recorded transition bounds and
        # all later accepted measurements. Arrival time is never capture time.
        for k in range(packet.capture, self.epoch+1):
            if k > packet.capture:
                self.priors[k] = {m: predict(r, self.transitions[k-1], self.dt)
                                  for m, r in self.posts[k-1].items()}
            bank = dict(self.priors[k])
            for event in self.events.get(k, []):
                bank = self.correct(bank, event)
            self.posts[k] = bank
        if any(m not in before or not r.subset(before[m]) for m, r in self.bank.items()):
            raise AssertionError("same-epoch replay enlarged the compatible region")
        self.refinement_checks += 1
        self.last_capture = max(packet.capture, self.last_capture if self.last_capture is not None else packet.capture)
        if not self.bank:
            self.inconsistent = True
            return "INCONSISTENT"
        return "APPLIED"

    def advance(self, acceleration):
        if acceleration[0] > acceleration[1]:
            raise ValueError("invalid actuator interval")
        self.transitions[self.epoch] = acceleration
        bank = {m: predict(r, acceleration, self.dt) for m, r in self.bank.items()}
        self.epoch += 1
        self.priors[self.epoch] = bank
        self.posts[self.epoch] = dict(bank)
        self.events[self.epoch] = []
        floor = self.epoch-self.window
        for table in (self.priors, self.posts, self.events, self.transitions):
            for k in list(table):
                if k < floor:
                    del table[k]


def stop_requirement(v, decel, delay, coast_accel, delta=Q(1, 5)):
    v, decel, delay, coast_accel, delta = map(rational, (v, decel, delay, coast_accel, delta))
    if v < 0 or decel <= 0 or delay < 0 or coast_accel < 0:
        raise ValueError("invalid stopping contract")
    return delta+v*delay+coast_accel*delay*delay/2+(v+coast_accel*delay)**2/(2*decel)


def admissible(bank, *, dt=Q(1, 100), decel=Q(4, 5), coast_accel=Q(1, 50)):
    if not bank:
        return set()
    dlo = min(r.bounds(0)[0] for r in bank.values())
    vhi = max(r.bounds(1)[1] for r in bank.values())
    return {action for action, delay in (("BRAKE", dt), ("COAST", 2*dt))
            if dlo >= stop_requirement(vhi, decel, delay, coast_accel)}


def command(observer, **bounds):
    if not observer.valid:
        return "BRAKE", "INVALID_OR_STALE"
    actions = admissible(observer.bank, dt=observer.dt, **bounds)
    if "COAST" in actions:
        return "COAST", "CERTIFIED_MODEL"
    return "BRAKE", "CERTIFIED_MODEL" if "BRAKE" in actions else "OUTSIDE_STOPPING_CONTRACT"
