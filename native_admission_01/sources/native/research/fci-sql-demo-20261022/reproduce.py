"""Real Linux UID/AF_UNIX/SQLite D0 experiment. Run in a disposable root container.

The privileged controller provisions fixtures and reads the target oracle. It
does not give its additional observations to the service during fault tests.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from adapter import OPERATION, SCHEMA
from fci_hardened.fixture_setup import provision
from fci_hardened.strict_json import canonical
from fci_hardened.service import clock
from lifecycle import Local, fixture_rearm, HOLD
from base01.authority import State, fixture_witness

SUID, RUID, MUID, OTHER = 61051, 61052, 61053, 61054
FROZEN = "7a0784a4dc8d9953487ebeb54bd42df834d40eb4"


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def recv(conn, n):
    buf = b""
    while len(buf) < n:
        part = conn.recv(n - len(buf))
        if not part:
            raise EOFError("connection closed before complete response")
        buf += part
    return buf


def peer_request(args, request, drop=False):
    if args.direct:
        try:
            with sqlite3.connect("file:" + args.runtime + "/consumer.db?mode=rw", uri=True) as db:
                db.execute("UPDATE demo_configuration SET value=9")
            return {"direct_write": "SUCCEEDED"}
        except sqlite3.Error:
            return {"direct_write": "DENIED"}
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(5)
        conn.connect(args.socket)
        payload = canonical(request)
        conn.sendall(struct.pack("!I", len(payload)) + payload)
        if drop:
            return {"code": "OUTCOME_UNKNOWN_CLIENT_RESPONSE_NOT_READ", "new_effect": None}
        length = struct.unpack("!I", recv(conn, 4))[0]
        return json.loads(recv(conn, length))


def peer(args):
    if not args.peer_loop:
        print(json.dumps(peer_request(args, json.loads(sys.stdin.read() or "{}"), args.drop)))
        return
    print(json.dumps({"peer_uid":os.geteuid(),"pid":os.getpid()}),flush=True)
    for line in sys.stdin:
        envelope=json.loads(line)
        try: result=peer_request(args,envelope["request"],envelope.get("drop",False))
        except (OSError,EOFError,TimeoutError):result={"code":"OUTCOME_UNKNOWN_TRANSPORT","new_effect":None}
        print(json.dumps(result),flush=True)


class Fixture:
    def __init__(self, parent, name, fault="none"):
        self.base = parent / name
        self.runtime, self.keys, _ = provision(self.base, SUID, RUID, MUID)
        self.socket = self.base / "ipc" / "fci.sock"
        self.journal = self.base / "events.jsonl"
        self.journal.touch(mode=0o600)
        os.chown(self.journal, SUID, SUID)
        operation = self.runtime / "demo-operation.json"
        operation.write_bytes(canonical(OPERATION)); os.chmod(operation, 0o600); os.chown(operation, SUID, SUID)
        with sqlite3.connect(self.runtime / "consumer.db") as db:
            db.executescript("""
            CREATE TABLE demo_configuration(target TEXT PRIMARY KEY,version INTEGER NOT NULL,value INTEGER NOT NULL);
            CREATE TABLE demo_effects(event_id INTEGER PRIMARY KEY,operation_id TEXT NOT NULL,target TEXT NOT NULL,
                old_version INTEGER NOT NULL,new_version INTEGER NOT NULL,value INTEGER NOT NULL);
            INSERT INTO demo_configuration VALUES('synthetic-config',0,0);
            """)
        self.calls = []
        self.peers = {}
        self.peer_receipts = []
        self.process = None
        self.start(fault)

    def start(self, fault="none"):
        self.process = subprocess.Popen(
            [sys.executable, str(HERE / "adapter.py"), str(self.runtime), "--journal", str(self.journal), "--fault", fault],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            user=SUID, group=SUID, extra_groups=[])
        ready, _, _ = select.select([self.process.stdout], [], [], 10)
        line = self.process.stdout.readline() if ready else ""
        if not line.startswith("READY "):
            self.process.kill(); _, err = self.process.communicate(timeout=5)
            raise RuntimeError("service startup failed: " + err)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.kill(); self.process.communicate(timeout=5)

    def close(self):
        self.stop()
        for p in self.peers.values():
            if p.poll() is None:p.kill()
            p.communicate(timeout=5)

    def call(self, req, uid=RUID, drop=False):
        if uid not in self.peers:
            command=[sys.executable,str(HERE/"reproduce.py"),"--peer-loop","--socket",str(self.socket)]
            p=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                               text=True,user=uid,group=uid,extra_groups=[])
            ready,_,_=select.select([p.stdout],[],[],10)
            if not ready:raise RuntimeError("requester worker startup timeout")
            receipt=json.loads(p.stdout.readline());assert receipt["peer_uid"]==uid,receipt
            self.peer_receipts.append(receipt);self.peers[uid]=p
        p=self.peers[uid];started=time.monotonic_ns()
        p.stdin.write(json.dumps({"request":req,"drop":drop})+"\n");p.stdin.flush()
        ready,_,_=select.select([p.stdout],[],[],10)
        if not ready:raise RuntimeError("requester response timeout")
        result=json.loads(p.stdout.readline())
        self.calls.append({"op": req["op"], "uid": uid,"started_monotonic_ns":started,
                           "completed_monotonic_ns":time.monotonic_ns(),
                           "response": {k:v for k,v in result.items() if k != "ticket"}})
        return result

    def observe(self):
        with sqlite3.connect(f"file:{self.runtime}/consumer.db?mode=ro", uri=True) as db:
            config = db.execute("SELECT target,version,value FROM demo_configuration").fetchall()
            effects = db.execute("SELECT operation_id,target,old_version,new_version,value FROM demo_effects ORDER BY event_id").fetchall()
            local = json.loads(db.execute("SELECT payload FROM consumer WHERE id=1").fetchone()[0])
        return {"configuration": config, "effects": effects, "mask": local["mask"],
                "observer": "DISTINCT_READ_ONLY_SQLITE_CONNECTION_PRIVILEGED_CONTROLLER"}

    def commission(self):
        # Explicit maintainer IPC, with witnesses from the trusted disposable
        # experiment controller. These are not real-world repair evidence.
        view = self.call({"op": "rearm_state"}, MUID)
        if view["authority"]["mask"]:
            witness = fixture_witness(State(**view["authority"]), self.keys["rearm"], clock())
            r = self.call({"op": "rearm_authority", "witness": witness}, MUID)
            assert r["code"] == "REARM_ACCEPTED", r
        view = self.call({"op": "rearm_state"}, MUID)
        if view["consumer"]["mask"]:
            witness = fixture_rearm(Local(**view["consumer"]), self.keys["local_rearm"], clock())
            r = self.call({"op": "rearm_local", "witness": witness}, MUID)
            assert r["code"] == "REARM_LOCAL_ACCEPTED", r

    def prepared(self):
        r = self.call({"op": "propose", **OPERATION})
        assert "ticket" in r, r
        return r["ticket"]

    def delivered(self):
        ticket = self.prepared()
        r = self.call({"op": "deliver", "ticket": ticket})
        assert r["code"] == "DELIVERED", r
        return ticket

    def finish(self, drop=False):
        return self.call({"op": "finish", "request_id": OPERATION["operation_id"]}, drop=drop)


def campaign(out):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use a disposable Linux container with root for the UID experiment; service itself is non-root")
    for mapping in ("uid_map", "gid_map"):
        ranges=[tuple(map(int,line.split())) for line in Path("/proc/self/"+mapping).read_text().splitlines()]
        if not all(any(start <= uid < start+length for start, _, length in ranges)
                   for uid in (SUID,RUID,MUID,OTHER)):
            raise RuntimeError("NOT_RUN_ENVIRONMENT: distinct experimental UIDs are not mapped; use the Linux CI runner")
    out.mkdir(parents=True, exist_ok=False)
    # A fresh readable copy avoids giving child UIDs access to a private checkout.
    # The workflow/controller must arrange readable source files, never runtime keys.
    cases = []
    with tempfile.TemporaryDirectory(prefix="fci-sql-d0-") as tmp:
        parent = Path(tmp); os.chmod(parent, 0o755)
        def run(name, fn, fault="none"):
            f = Fixture(parent, name, fault)
            try:
                initial = f.observe()
                f.commission()
                findings = fn(f)
                final = f.observe()
                events = [json.loads(line) for line in f.journal.read_text().splitlines()]
                case = {"id": name, "status": "PASS_EXECUTED_SCOPED", "initial": initial,
                        "final": final, "calls": f.calls, "events": events, "findings": findings,
                        "peer_receipts":f.peer_receipts}
                cases.append(case)
                save(out/(name+".json"),case)
            except BaseException as error:
                save(out/(name+".json"),{"id":name,"status":"FAIL_EXECUTED",
                    "error_type":type(error).__name__,"error":str(error),
                    "calls":f.calls,"observed":f.observe(),"peer_receipts":f.peer_receipts,
                    "events":[json.loads(line) for line in f.journal.read_text().splitlines()]})
                raise
            finally:
                f.close()

        def nominal(f):
            f.delivered(); r = f.finish(); assert r == {"code": "EFFECT_COMMITTED", "new_effect": True}, r
            before = f.observe(); assert before["configuration"] == [("synthetic-config", 1, 1)]
            assert len(before["effects"]) == 1
            r = f.finish(); assert r == {"code": "ACK_EFFECT_HISTORY", "new_effect": False}, r
            assert f.observe() == before
            return ["one actual configuration transition and one effect row; same-ID replay adds nothing"]
        run("NOMINAL_AND_REPLAY", nominal)

        def altered(f):
            for key, value in (("target","other"),("expected_version",1),("value",0),("operation_id","CFG002")):
                req = {"op":"propose", **OPERATION, key:value}
                assert f.call(req)["code"] == "BLOCK_DEMO_OPERATION"
            assert f.call({"op":"propose", **OPERATION}, MUID)["code"] == "BLOCK_ROLE"
            assert f.call({"op":"fixture_conditions", "healthy":False})["code"] == "BLOCK_ROLE"
            assert f.call({"op":"prepare","request_id":"CFG001","action":"BRAKE"})["code"] == "BLOCK_DEMO_OPERATION"
            assert not f.observe()["effects"]
            return ["four altered operation fields and wrong roles refused; no configuration mutation"]
        run("ALTERED_OPERATION_AND_ROLES", altered)

        def ticket(f):
            original = f.prepared(); changed = copy.deepcopy(original)
            changed["token"]["body"]["action"]["value"] = 0
            assert f.call({"op":"deliver", "ticket":changed})["code"] == "BLOCK_INPUT"
            assert not f.observe()["effects"]
            assert f.call({"op":"deliver", "ticket":original})["code"] == "DELIVERED"
            r=f.finish(); assert r["new_effect"] is True, r
            assert len(f.observe()["effects"]) == 1
            return ["tampered signed ticket refused; original remains usable once"]
        run("TAMPERED_TICKET", ticket)

        def expired(f):
            f.delivered();started=time.monotonic();time.sleep(HOLD+.1)
            assert time.monotonic()-started>=HOLD
            r=f.finish();assert r["code"].startswith("BLOCK_") and r["new_effect"] is False,r
            assert not f.observe()["effects"]
            return ["real elapsed time exceeds the unchanged LIFE01 HOLD; expired operation has no target effect"]
        run("EXPIRED_PERMISSION",expired)

        def latch(f):
            f.delivered()
            f.call({"op":"fixture_conditions","healthy":False}, MUID)
            r=f.finish(); assert r["code"].startswith("BLOCK_") and r["new_effect"] is False, r
            assert f.observe()["mask"] & 1
            f.call({"op":"fixture_conditions","healthy":True}, MUID)
            for _ in range(10):
                r=f.finish(); assert r["code"].startswith("BLOCK_") and r["new_effect"] is False, r
            f.stop(); f.start()
            assert f.observe()["mask"] & 1
            assert f.finish()["new_effect"] is False
            invalid=f.call({"op":"rearm_local","witness":{}},MUID)
            assert invalid["code"].startswith("BLOCK_"), invalid
            assert f.observe()["mask"] & 1
            f.commission(); assert f.observe()["mask"] == 0
            r=f.finish(); assert r["code"].startswith("BLOCK_") and r["new_effect"] is False, r
            assert f.observe()["configuration"] == [("synthetic-config",0,0)]
            assert not f.observe()["effects"]
            return ["fault cause persists across healthy context and real SIGKILL/restart",
                    "invalid witness refused; explicit maintainer rearm clears cause without an effect",
                    "old delivered permission remains unusable after rearm",
                    "fresh logical operation after rearm is outside D0, not claimed"]
        run("LATCH_RESTART_AND_REARM", latch)

        def lost(f):
            f.delivered(); r=f.finish(drop=True)
            assert r["new_effect"] is None
            # Wait for an actual durable observation, bounded by a test deadline.
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                if len(f.observe()["effects"]) == 1: break
                time.sleep(.01)
            assert len(f.observe()["effects"]) == 1
            r=f.finish(); assert r == {"code":"ACK_EFFECT_HISTORY","new_effect":False}, r
            assert len(f.observe()["effects"]) == 1
            return ["client deliberately discards response and records UNKNOWN; oracle observes actual effect",
                    "same-ID query returns history without a second target mutation"]
        run("RESPONSE_NOT_READ", lost)

        def cut(f, expected):
            f.delivered(); r=f.finish(); assert r["new_effect"] is None, r
            assert f.process.wait(timeout=5) == 73
            before=f.observe(); assert len(before["effects"]) == expected
            assert before["configuration"][0][1:] == (expected, expected)
            f.start(); replay=f.finish()
            assert replay["new_effect"] is False, replay
            assert len(f.observe()["effects"]) == expected
            return ["actual service process exit 73 at instrumented transaction boundary",
                    "configuration and effect row agree after independent reopening",
                    "restart/replay adds no target mutation; pre-commit recovery remains conservative"]
        run("CUT_BEFORE_COMMIT",lambda f:cut(f,0),"before_commit")
        run("CUT_AFTER_COMMIT",lambda f:cut(f,1),"after_commit")

        def rights(f):
            command=[sys.executable,str(HERE/"reproduce.py"),"--peer","--direct","--runtime",str(f.runtime)]
            result=subprocess.run(command,capture_output=True,text=True,user=RUID,group=RUID,extra_groups=[],timeout=10)
            assert result.returncode == 0 and json.loads(result.stdout) == {"direct_write":"DENIED"}
            assert f.call({"op":"status"},OTHER)["code"] == "BLOCK_ROLE"
            assert not f.observe()["effects"]
            f.delivered(); assert f.finish()["new_effect"] is True
            return ["actual requester UID cannot open target database for mutation",
                    "SO_PEERCRED rejects another UID; normal requester IPC still works",
                    "trusted administrator/service UID remain outside this bypass claim"]
        run("REQUESTER_WRITE_DENIED", rights)

    source_files=sorted(list((HERE).glob("*.py")))
    source_files += [ROOT / f["path"] for f in json.loads((HERE/"SOURCE_FREEZE.json").read_text())["files"]]
    hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
    receipt={"schema":SCHEMA,"status":"PASS_EXECUTED_SCOPED","executed_utc":datetime.now(timezone.utc).isoformat(),
             "reference_commit":FROZEN,"python":platform.python_version(),"platform":platform.platform(),
             "controller_uid":os.geteuid(),"service_uid":SUID,"requester_uid":RUID,"maintainer_uid":MUID,
             "case_count":len(cases),"cases":cases,"source_sha256":hashes,
             "global_claims":{"qualification":"HOLD/OPEN","NONLEAK_END_TO_END":False,
                              "physical_tests":"NOT_RUN","full_P01_P14":"NOT_COMPLETE"}}
    save(out/"RESULTS.json",receipt)
    print(json.dumps({"status":receipt["status"],"cases":len(cases),"results":str(out/"RESULTS.json")}))


def main():
    ap=argparse.ArgumentParser();ap.add_argument("--output",type=Path)
    ap.add_argument("--peer",action="store_true");ap.add_argument("--peer-loop",action="store_true");ap.add_argument("--socket")
    ap.add_argument("--drop",action="store_true");ap.add_argument("--direct",action="store_true");ap.add_argument("--runtime")
    args=ap.parse_args()
    if args.peer or args.peer_loop: peer(args)
    elif args.output: campaign(args.output)
    else: ap.error("--output required")


if __name__ == "__main__": main()
