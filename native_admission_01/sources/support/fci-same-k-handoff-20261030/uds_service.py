"""SAME-K-HANDOFF-02: Linux local service, retained SQL store, fixed UID policy.

Privileged provisioning is external. Root, the service UID, kernel, interpreter,
dependencies and provisioning authority remain trusted. Not a native FCI bridge.
"""
import argparse
import array
from concurrent.futures import ThreadPoolExecutor
import ctypes
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time

# -I ignores cwd/PYTHONPATH; only this administrator-owned source directory added.
sys.path.insert(0, str(Path(__file__).parent))
from handoff import Destination, Refused, canonical, issue_permit, need, public, shape, strict_loads
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

UCRED = struct.Struct("3i")
MAX_FRAME = 65536


def private_file(path, owner, mode):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == owner and stat.S_IMODE(s.st_mode) == mode, "FILE_POLICY")
        return f.read(MAX_FRAME + 1)


def directory(path, owner, mode):
    s = Path(path).lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == owner and stat.S_IMODE(s.st_mode) == mode, "DIRECTORY_POLICY")


def harden():
    libc = ctypes.CDLL(None, use_errno=True)
    need(libc.prctl(38, 1, 0, 0, 0) == 0, "NO_NEW_PRIVS")
    need(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0, "DUMPABLE")
    status = dict(line.split(":", 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(int(status['CapEff'].strip(), 16) == 0 and not os.getgroups(), "PRIVILEGES")
    return {"uid": os.getuid(), "euid": os.geteuid(), "cap_eff": status['CapEff'].strip(), "no_new_privs": status['NoNewPrivs'].strip(), "dumpable": 0}


class Service:
    def __init__(self, config_path):
        directory(Path(config_path).parent, 0, 0o755)
        cfg = strict_loads(private_file(config_path, 0, 0o444))
        shape(cfg, ('schema', 'service_uid', 'state_dir', 'socket', 'identities'))
        need(cfg['schema'] == 'SAME-K-LOCAL/1', 'CONFIG_SCHEMA')
        uid = cfg['service_uid']
        need(type(uid) is int and uid > 0 and os.getuid() == os.geteuid() == uid, 'SERVICE_UID')
        directory(Path(__file__).parent, 0, 0o555)
        for file in ('uds_service.py', 'handoff.py'):
            private_file(Path(__file__).parent / file, 0, 0o444)
        identities = cfg['identities']
        shape(identities, ('controller', 'A', 'B'))
        values = list(identities.values())
        need(all(type(x) is int and x > 0 and x != uid for x in values) and len(set(values)) == 3, 'UID_POLICY')
        self.roles = {v: k for k, v in identities.items()}
        self.identity = harden()
        self.state = Path(cfg['state_dir'])
        directory(self.state, uid, 0o700)
        self.socket_path = Path(cfg['socket'])
        directory(self.socket_path.parent, uid, 0o755)
        self.sink_key = Ed25519PrivateKey.from_private_bytes(private_file(self.state/'sink.key', uid, 0o600))
        self.issuer_key = Ed25519PrivateKey.from_private_bytes(private_file(self.state/'issuer.key', uid, 0o600))
        private_file(self.state/'destination.db', uid, 0o600)
        self.destination = Destination(self.state/'destination.db', self.sink_key)
        need(self.destination.meta['controller'] == 'controller' and self.destination.meta['issuer_public'] == public(self.issuer_key), 'STORE_CONFIG')

    def dispatch(self, request, actor):
        shape(request, ('op', 'args'))
        op, args = request['op'], request['args']
        need(type(op) is str and type(args) is dict, 'REQUEST')
        fields = {
            'whoami': (), 'bind': ('key', 'content'),
            'assign': ('key', 'h', 'expected_generation', 'subject', 'request_id'),
            'resolve': ('key', 'h', 'generation', 'attempt_id', 'challenge'),
            'issue': ('allocation',), 'grant_read': ('key', 'h', 'subject'),
            'read_result': ('key', 'h'), 'execute': ('permit', 'content'),
        }
        need(op in fields, 'UNKNOWN_OPERATION')
        shape(args, fields[op])
        if op in ('bind', 'assign', 'resolve', 'issue', 'grant_read'):
            need(actor == 'controller', 'CONTROL_ROLE')
        d = self.destination
        if op == 'whoami':
            return {'principal': actor, 'service': self.identity}
        if op == 'bind':
            return d.bind(args['key'], args['content'], actor=actor)
        if op == 'assign':
            need(args['subject'] in ('A', 'B'), 'SUBJECT_POLICY')
            return d.assign(args['key'], args['h'], args['expected_generation'], args['subject'], args['request_id'], actor=actor)
        if op == 'resolve':
            return d.resolve(args['key'], args['h'], args['generation'], args['attempt_id'], args['challenge'], actor=actor)
        if op == 'issue':
            return issue_permit(args['allocation'], self.issuer_key, public(self.sink_key), int(time.time()))
        if op == 'grant_read':
            need(args['subject'] in ('A', 'B'), 'SUBJECT_POLICY')
            return d.grant_read(args['key'], args['h'], args['subject'], actor=actor)
        if op == 'read_result':
            return d.read_result(args['key'], args['h'], actor=actor)
        if op == 'execute':
            return d.execute(args['permit'], args['content'], actor=actor)
        raise Refused('UNKNOWN_OPERATION')

    def handle(self, conn):
        with conn:
            conn.settimeout(2)
            observation = None
            try:
                # SO_PEERCRED is the connecting identity, not a self-declared field.
                peer = UCRED.unpack(conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, UCRED.size))
                raw, ancillary, flags, _ = conn.recvmsg(MAX_FRAME + 1, 4096)
                credentials = []
                extra = False
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == UCRED.size:
                        credentials.append(UCRED.unpack(data))
                    else:
                        extra = True
                        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                            fds = array.array('i')
                            fds.frombytes(data[:len(data)//fds.itemsize*fds.itemsize])
                            for fd in fds:
                                os.close(fd)
                need(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and not extra, 'FRAME_OR_ANCILLARY')
                need(credentials == [peer], 'CREDENTIAL_MISMATCH')
                observation = dict(pid=peer[0], uid=peer[1], gid=peer[2])
                need(peer[1] in self.roles, 'UNKNOWN_UID')
                result = self.dispatch(strict_loads(raw), self.roles[peer[1]])
                response = {'ok': True, 'result': result, 'peer': observation}
            except Refused as exc:
                response = {'ok': False, 'error': str(exc), 'peer': observation}
            except (OSError, ValueError, TypeError, KeyError, OverflowError):
                response = {'ok': False, 'error': 'INTERNAL_HOLD', 'peer': observation}
            try:
                conn.sendall(canonical(response))
            except OSError:
                pass  # A lost reply never reverses the already committed result.

    def serve(self):
        os.umask(0o077)
        # Never remove an existing socket: its owner may still be serving.
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o666)
            listener.listen(16)
            print(canonical({'ready': True, 'pid': os.getpid(), 'service': self.identity}).decode(), flush=True)
            with ThreadPoolExecutor(max_workers=4) as workers:
                while True:
                    conn, _ = listener.accept()
                    workers.submit(self.handle, conn)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    Service(parser.parse_args().config).serve()
