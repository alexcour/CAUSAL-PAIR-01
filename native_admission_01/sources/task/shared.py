"""Disposable research harness utilities, no native engines imported."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

OWNER, CONTROL, A, B, UNKNOWN = range(62021, 62026)
CASES = ('FENCE_FIRST','FROZEN_CONTROL','COMMIT_FIRST','LOST_ACK_AFTER_COMMIT','COMMIT_DENIED','ROLLBACK_DENIED','OTHER_EXCEPTION','BAD_CERTIFICATE','INCOMPLETE_WITNESS','POST_RESERVATION_ABORT')

def commit_race(case):
    return case in ('COMMIT_FIRST','LOST_ACK_AFTER_COMMIT','COMMIT_DENIED','POST_RESERVATION_ABORT')
ROOTS = ('native', 'support', 'reference', 'recovery')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def get(path):
    return json.loads(Path(path).read_text())


def put(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.tmp-' + str(os.getpid()))
    with temp.open('w') as out:
        json.dump(value, out, sort_keys=True, allow_nan=False)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def setup(args):
    parent = module(args.recovery_root / 'run_recovery.py', 'received_recovery_runner')
    native, Bridge = parent.setup(args)
    return parent, native, Bridge


def arguments(p):
    for name in ROOTS:
        p.add_argument('--' + name + '-root', type=Path)


def root_flags(args):
    result = []
    for n in ROOTS:
        result += ['--' + n + '-root', str(getattr(args, n + '_root'))]
    return result


def python():
    return [sys.executable] + ([] if __debug__ else ['-O']) + ['-I', '-B']


def until(check, reason, timeout=12):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = check()
        if v:
            return v
        time.sleep(.01)
    raise TimeoutError(reason)


def events(path):
    if not Path(path).exists():
        return []
    rows = []
    for line in Path(path).read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # live poll only; offline receiver parses every final line strictly
    return rows
