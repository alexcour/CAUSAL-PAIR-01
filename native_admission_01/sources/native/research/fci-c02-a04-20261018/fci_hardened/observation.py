"""Service-owned IF1 dependencies for an explicitly synthetic observation.

Time comes from the server's monotonic clock. The 0.01 s discretization and
unbounded OS scheduling prevent any hardware/WCET claim. No sensor is attached.
"""
import time
import uuid
from fractions import Fraction as Q

from .strict_json import rational
from .vendor import Observer, Region, Identity, Frame, ObservationBoundary


class Observation:
    def __init__(self, policy):
        self.policy = policy
        p = policy.body
        f, o = p["fixture"], p["observer"]
        d, v = rational(f["distance"]), rational(f["velocity"])
        self.origin_ns = time.monotonic_ns()
        self.last_ns = self.origin_ns
        self.observer = Observer({"nominal": Region.convex([(d, v)])}, {"nominal": Q(0)},
                                 dt=rational(o["dt"]), distance_noise=Q(0), speed_noise=Q(0),
                                 probe_noise=Q(0), history=o["history"], max_age=o["max_age"])
        identity = Identity("FCI-OBS-IF/1", p["model"], policy.digest, uuid.uuid4().hex,
                            "service-monotonic-10ms", ("m", "m/s"))
        self.boundary = ObservationBoundary(self.observer, identity)
        code = self.boundary.receive(Frame(identity, "primary", 1, 0, 0, 0, "primary", d, v, True))
        if code != "APPLIED":
            raise ValueError("initial synthetic observation rejected")
        self.valid_until = rational(p["valid_for"])
        self.acceleration = (rational(o["acceleration_low"]), rational(o["acceleration_high"]))
        self.advance_limit = o["advance_limit"]

    def decide(self):
        ns = time.monotonic_ns()
        target = (ns - self.origin_ns) // 10_000_000
        count = target - self.observer.epoch
        if ns < self.last_ns or count < 0 or count > self.advance_limit:
            self.boundary.fault_latched = True
        else:
            for _ in range(count):
                self.observer.advance(self.acceleration)
        self.last_ns = max(self.last_ns, ns)
        # Both parameters are owned by the authenticated policy, never IPC input.
        return self.boundary.decide(self.boundary.snapshot(self.valid_until), self.policy.budgets)
