"""FCI-JCS-INT/1: bounded JSON with JCS serialization on the accepted subset.

Deliberately rejects floating-point tokens, Decimal and arbitrary Python objects.
This is not a general-purpose implementation of RFC 8785 number serialization.
"""
import json
import math
from fractions import Fraction

MAX_BYTES = 65536
MAX_INT = 2**53 - 1
MAX_DEPTH = 16
MAX_NODES = 4096
MAX_STRING = 8192


class InputError(ValueError):
    pass


def integer(value, low=-MAX_INT, high=MAX_INT):
    if type(value) is not int or not low <= value <= high:
        raise InputError("integer range/type")
    return value


def shape(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise InputError("object fields")
    return value


def rational(value):
    shape(value, ("n", "d"))
    n, d = integer(value["n"], -10**9, 10**9), integer(value["d"], 1, 10**6)
    if math.gcd(n, d) != 1:
        raise InputError("rational must be reduced with positive denominator")
    return Fraction(n, d)


def string(value):
    if type(value) is not str or len(value) > MAX_STRING:
        raise InputError("string range/type")
    try:
        value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise InputError("lone surrogate") from exc
    return value


def validate(value):
    count = 0

    def walk(v, depth):
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise InputError("structural limit")
        if v is None or type(v) is bool:
            return
        if type(v) is int:
            integer(v)
        elif type(v) is str:
            string(v)
        elif type(v) is list:
            for item in v:
                walk(item, depth + 1)
        elif type(v) is dict:
            for key, item in v.items():
                walk(string(key), depth + 1)
                walk(item, depth + 1)
        else:
            raise InputError("outside JSON integer profile")

    walk(value, 0)
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate property")
        result[key] = value
    return result


def _parse_int(token):
    if len(token) > 17 or token == "-0":
        raise InputError("integer token")
    return integer(int(token))


def _no_number(token):
    raise InputError("non-integer numeric token")


def loads(data):
    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise InputError("byte payload limit/type")
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_pairs, parse_int=_parse_int,
                           parse_float=_no_number, parse_constant=_no_number)
        return validate(value)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError("invalid JSON") from exc


def canonical(value):
    validate(value)

    def emit(v):
        if v is None:
            return "null"
        if type(v) is bool:
            return "true" if v else "false"
        if type(v) is int:
            return str(v)
        if type(v) is str:
            return json.dumps(v, ensure_ascii=False, allow_nan=False)
        if type(v) is list:
            return "[" + ",".join(emit(x) for x in v) + "]"
        # UTF-16 code unit order, not Python Unicode code point order.
        return "{" + ",".join(emit(k) + ":" + emit(v[k]) for k in
                               sorted(v, key=lambda k: k.encode("utf-16-be"))) + "}"

    result = emit(value).encode("utf-8")
    if len(result) > MAX_BYTES:
        raise InputError("canonical payload limit")
    return result
