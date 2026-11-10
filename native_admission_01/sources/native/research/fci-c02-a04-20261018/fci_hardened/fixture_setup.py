"""Offline disposable provisioning helpers. Not imported by the service.

Root, policy signer and repair verifier are trusted in the local experiment.
No production credentials or automatic repair oracle are supplied by this lot.
"""
import hashlib
import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from .policy import DOMAIN, UNITS, verify_policy
from .service import CONTEXT, KEY_NAMES
from .strict_json import canonical
from .spend_ledger import SpendLedger
from .finalizing_consumer import FinalizingConsumer
from .vendor import Consumer, DispatchAuthority, SQLiteSinkAnchor, State, STARTUP


def example_body(distance=None, velocity=None, valid_for=None):
    q = lambda n, d=1: {"n": n, "d": d}
    return {
        "schema": "FCI-C02-POLICY/1", "mode": "SOFTWARE_FIXTURE",
        "model": "planar-offset/v1", "config_name": "synthetic-c02-a04",
        "units": dict(UNITS),
        "budgets": {"compute_queue": q(0), "actuator": q(1, 100), "hold": q(1, 100),
                    "deceleration": q(4, 5), "coast_acceleration": q(1, 50), "residual_distance": q(1, 5)},
        "valid_for": valid_for if valid_for is not None else q(600),
        "provenance": {"bounds": "SYNTHETIC_ONLY", "reference": "C02-A04-C003-C004-20261018-RC3 test fixture; no physical calibration"},
        "observer": {"dt": q(1, 100), "max_age": 60000, "history": 8, "advance_limit": 10000,
                     "acceleration_low": q(0), "acceleration_high": q(0)},
        "fixture": {"distance": distance if distance is not None else q(10),
                    "velocity": velocity if velocity is not None else q(0), "conditions": [True]*5},
        "action_levels": {"BRAKE": 0, "COAST": 1},
    }


def sign(body, signer):
    public = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pack = {"body": body, "key_id": hashlib.sha256(public).hexdigest(),
            "signature": signer.sign(DOMAIN + canonical(body)).hex()}
    return canonical(pack), public


def provision(base, service_uid, requester_uid, maintainer_uid, body=None):
    """A new directory only. Keys random per fixture and never returned by IPC."""
    base = Path(base)
    base.mkdir(mode=0o755)
    runtime, sockdir = base / "state", base / "ipc"
    runtime.mkdir(mode=0o700)
    sockdir.mkdir(mode=0o755)
    signer = Ed25519PrivateKey.generate()
    payload, public = sign(example_body() if body is None else body, signer)
    policy = verify_policy(payload, public)
    keys = {name: secrets.token_bytes(32) for name in KEY_NAMES}
    cfg = {"schema": "FCI-C02-DEPLOY/1", "service_uid": service_uid, "requester_uid": requester_uid,
           "maintainer_uid": maintainer_uid, "socket_dir": str(sockdir.absolute())}
    for name, data in (("deployment.json", canonical(cfg)), ("policy.json", payload), ("policy-public.key", public),
                       ("keys.json", canonical({n: v.hex() for n, v in keys.items()}))):
        fd = os.open(runtime / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
    an = SQLiteSinkAnchor.provision(runtime / "anchor.db", keys["anchor"],
                                    State("I", policy.digest, CONTEXT, STARTUP, 0, 0), keys["token"], keys["receipt"])
    a = DispatchAuthority.bootstrap(runtime / "replica.db", keys["state"], keys["rearm"], "I", policy.digest, CONTEXT, an)
    c = Consumer.provision(runtime / "consumer.db", keys["effect"], keys["token"], keys["receipt"], keys["local_rearm"])
    r = c.set_scope(policy.digest, CONTEXT, an, now=0)
    if r.code != "LOCAL_SCOPE_RECORDED":
        raise ValueError("initial scope")
    FinalizingConsumer.provision_journal(c.db)
    c.close(); a.close(); an.close()
    ledger = SpendLedger.provision(runtime / "spend.db", keys["spend"],
                                  {"instance": "I", "target": "SIM_SINK", "policy": policy.digest, "context": CONTEXT})
    ledger.close()
    if os.geteuid() != 0:
        raise PermissionError("fixture provisioning requires root for distinct test UIDs")
    for f in runtime.iterdir():
        os.chmod(f, 0o600)
        if (f.stat().st_uid, f.stat().st_gid) != (service_uid, service_uid):
            os.chown(f, service_uid, service_uid)
    for directory in (runtime, sockdir):
        if (directory.stat().st_uid, directory.stat().st_gid) != (service_uid, service_uid):
            os.chown(directory, service_uid, service_uid)
    return runtime, keys, signer
