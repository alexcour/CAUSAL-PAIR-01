"""One bounded kernel-authenticated RPC. Never retries an uncertain call."""
import argparse
import json
import os
import socket
import struct


class OutcomeUnknown(Exception):
    pass


def call(path, request):
    raw = json.dumps(request, allow_nan=False).encode()
    if len(raw) > 65536:
        raise ValueError('FRAME')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
        conn.settimeout(45)
        conn.connect(path)
        peer = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer[1] != 62021:
            raise ValueError('SERVER_UID')
        conn.sendall(raw)
        data = conn.recv(2097152)
    if not data:
        raise OutcomeUnknown('NATIVE_EOF_NO_ACK')
    result = json.loads(data)
    if type(result.get('ok')) is not bool or result.get('peer') != dict(pid=os.getpid(), uid=os.getuid(), gid=os.getgid()):
        raise ValueError('PEER_BINDING')
    return result


if __name__ == '__main__':
    import sys
    p = argparse.ArgumentParser()
    p.add_argument('--socket', required=True)
    a = p.parse_args()
    result = call(a.socket, json.load(sys.stdin))
    print(json.dumps(dict(response=result, client_pid=os.getpid(), client_uid=os.getuid())), flush=True)
