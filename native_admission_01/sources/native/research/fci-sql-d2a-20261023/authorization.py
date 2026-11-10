"""Exact SQL authorization for the D2-A research adapter, not the RC3 token.

Ed25519 and strict parameter binding are standard adapter mechanisms. A valid
envelope alone does not authorize an effect without the FCI and SQL guards.
"""
from __future__ import annotations

import hashlib
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "FCI-SQL-D2A-AUTHZ/1"
DOMAIN = SCHEMA.encode("ascii") + b"\x00"
NAMESPACE = "FCI_SQL_D2A_TEST"
KEY_ID = "D2A_FIXTURE_AUTHZ_1"
FIELDS = frozenset(("schema", "key_id", "namespace", "deployment_id", "operation_id",
                    "target", "action", "expected_version", "value", "subject_uid",
                    "subject_role", "policy_digest", "context", "authority_epoch",
                    "boot_id", "not_before", "not_after"))
OP_FIELDS = ("operation_id", "target", "expected_version", "value")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
RID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


class AuthorizationRefused(ValueError):
    pass


def require(flag, reason):
    if not flag:
        raise AuthorizationRefused(reason)


def exact_shape(value, fields):
    require(type(value) is dict and set(value) == set(fields), "SHAPE")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def strict_loads(raw):
    require(type(raw) is bytes and len(raw) <= 16384, "FRAME")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_KEY")
            result[key] = value
        return result
    def bad_constant(_):
        raise AuthorizationRefused("NUMBER")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise AuthorizationRefused("JSON") from error


def body_bytes(body):
    exact_shape(body, FIELDS)
    for name in FIELDS - {"expected_version", "value", "subject_uid", "authority_epoch",
                          "not_before", "not_after"}:
        require(type(body[name]) is str and body[name].isascii(), "STRING")
    for name, maximum in (("expected_version", 99), ("value", 1),
                          ("subject_uid", 2**31-1), ("authority_epoch", 2**63-2),
                          ("not_before", 2**63-1), ("not_after", 2**63-1)):
        require(type(body[name]) is int and 0 <= body[name] <= maximum, "INTEGER")
    require(body["subject_uid"] >= 1, "UID")
    require(body["schema"] == SCHEMA and body["key_id"] == KEY_ID
            and body["namespace"] == NAMESPACE, "DOMAIN")
    require(UUID.fullmatch(body["deployment_id"]) and UUID.fullmatch(body["boot_id"]), "UUID")
    require(RID.fullmatch(body["operation_id"]), "RID")
    require(body["target"] in ("synthetic-config", "synthetic-config-decoy")
            and body["action"] == "set_value", "ACTION")
    require(body["subject_role"] == "requester", "ROLE")
    require(re.fullmatch(r"[0-9a-f]{64}", body["policy_digest"]), "POLICY_DIGEST")
    require(body["not_before"] < body["not_after"] <= body["not_before"] + 30, "VALIDITY")
    return canonical(body)


def verify_signature(envelope, installed_public_key):
    exact_shape(envelope, ("body", "signature"))
    data = body_bytes(envelope["body"])
    signature = envelope["signature"]
    require(type(signature) is str and re.fullmatch(r"[0-9a-f]{128}", signature), "SIGNATURE")
    try:
        Ed25519PublicKey.from_public_bytes(installed_public_key).verify(
            bytes.fromhex(signature), DOMAIN + data)
    except (InvalidSignature, ValueError, TypeError) as error:
        raise AuthorizationRefused("SIGNATURE") from error
    return hashlib.sha256(DOMAIN + data).hexdigest()


def bind(envelope, operation, installed_public_key, *, uid, role, deployment_id,
         policy_digest, context, boot_id, epoch, now, history=False):
    digest = verify_signature(envelope, installed_public_key)
    body = envelope["body"]
    exact_shape(operation, OP_FIELDS)
    require(all(type(operation[k]) is type(body[k]) and operation[k] == body[k]
                for k in OP_FIELDS), "PARAMETER_BINDING")
    require(type(uid) is int and uid == body["subject_uid"]
            and role == body["subject_role"], "SUBJECT_BINDING")
    require((body["deployment_id"], body["policy_digest"], body["context"], body["boot_id"])
            == (deployment_id, policy_digest, context, boot_id), "CONTEXT_BINDING")
    if not history:
        require(type(epoch) is int and body["authority_epoch"] == epoch, "EPOCH_BINDING")
        require(type(now) is int and body["not_before"] <= now < body["not_after"], "EXPIRED")
    return digest
