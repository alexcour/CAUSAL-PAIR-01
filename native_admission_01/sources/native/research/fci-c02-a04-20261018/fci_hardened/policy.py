"""Authenticated parameters for a bounded software fixture, not ratification."""
from dataclasses import dataclass
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .strict_json import InputError, canonical, loads, shape, integer, rational
from .vendor import Budgets

DOMAIN = b"FCI-C02-A04/POLICY/1\x00"
BUDGET_NAMES = ("compute_queue", "actuator", "hold", "deceleration",
                "coast_acceleration", "residual_distance")
UNITS = {"distance": "m", "velocity": "m/s", "acceleration": "m/s2", "time": "s"}


@dataclass(frozen=True)
class Policy:
    digest: str
    canonical_body: bytes

    @property
    def body(self):
        # Return a new tree: callers cannot mutate the authenticated instance.
        return loads(self.canonical_body)

    @property
    def budgets(self):
        return Budgets(**{k: rational(v) for k, v in self.body["budgets"].items()})


def validate_body(body):
    shape(body, ("schema", "mode", "model", "config_name", "units", "budgets",
                 "valid_for", "provenance", "observer", "fixture", "action_levels"))
    if (body["schema"] != "FCI-C02-POLICY/1" or body["mode"] != "SOFTWARE_FIXTURE"
            or body["model"] != "planar-offset/v1" or body["units"] != UNITS):
        raise InputError("unsupported policy profile")
    if type(body["config_name"]) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", body["config_name"]):
        raise InputError("config name")
    shape(body["provenance"], ("bounds", "reference"))
    if any(type(v) is not str or not 1 <= len(v) <= 256 for v in body["provenance"].values()):
        raise InputError("missing provenance")
    shape(body["budgets"], BUDGET_NAMES)
    budgets = Budgets(**{k: rational(v) for k, v in body["budgets"].items()})
    if max(rational(v) for v in body["budgets"].values()) > 10**6:
        raise InputError("fixture budget range")
    if not 0 <= rational(body["valid_for"]) <= 3600:
        raise InputError("fixture validity range")
    o = shape(body["observer"], ("dt", "max_age", "history", "advance_limit",
                               "acceleration_low", "acceleration_high"))
    if not rational(o["dt"]) == rational({"n": 1, "d": 100}):
        raise InputError("fixture time step")
    integer(o["max_age"], 0, 60000)
    integer(o["history"], 0, 100)
    integer(o["advance_limit"], 1, 10000)
    alo, ahi = rational(o["acceleration_low"]), rational(o["acceleration_high"])
    # This candidate models only the declared zero-acceleration synthetic input.
    if alo != 0 or ahi != 0:
        raise InputError("unsupported fixture transition")
    f = shape(body["fixture"], ("distance", "velocity", "conditions"))
    if not 0 <= rational(f["distance"]) <= 1000 or not 0 <= rational(f["velocity"]) <= 100:
        raise InputError("fixture physical domain")
    if type(f["conditions"]) is not list or len(f["conditions"]) != 5 or any(type(x) is not bool for x in f["conditions"]):
        raise InputError("five exact condition booleans")
    shape(body["action_levels"], ("BRAKE", "COAST"))
    for level in body["action_levels"].values():
        integer(level, 0, 9)
    if len(set(body["action_levels"].values())) != 2:
        raise InputError("distinct simulated actions")
    return budgets


def verify_policy(payload, public_key):
    if type(public_key) is not bytes or len(public_key) != 32:
        raise InputError("pinned verification key")
    pack = shape(loads(payload), ("body", "key_id", "signature"))
    if pack["key_id"] != hashlib.sha256(public_key).hexdigest():
        raise InputError("untrusted key")
    if type(pack["signature"]) is not str or not re.fullmatch(r"[0-9a-f]{128}", pack["signature"]):
        raise InputError("signature encoding")
    body_bytes = canonical(pack["body"])
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(pack["signature"]), DOMAIN + body_bytes)
    except InvalidSignature as exc:
        raise InputError("policy signature") from exc
    validate_body(pack["body"])
    return Policy(hashlib.sha256(DOMAIN + body_bytes).hexdigest(), body_bytes)
