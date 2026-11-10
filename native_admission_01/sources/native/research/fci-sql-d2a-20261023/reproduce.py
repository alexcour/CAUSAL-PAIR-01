"""Bounded first integration campaign, with actual Linux UIDs and RC3 entry.

This is a subset of D2-A, not the 16-group qualification or the strong baseline.
Private signing keys stay in memory in the trusted disposable controller.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "fci-sql-demo-20261022"))
spec = importlib.util.spec_from_file_location("d0_sql_reproduce", HERE.parent / "fci-sql-demo-20261022/reproduce.py")
d0 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d0)
from authorization import DOMAIN, KEY_ID, NAMESPACE, OP_FIELDS, SCHEMA as AUTH_SCHEMA, canonical
from sql_service import SCHEMA
from fci_hardened.service import CONTEXT, clock


class Fixture(d0.Fixture):
    def __init__(self, parent, name, fault="none"):
        self.installed = False
        self.public_permits = []
        super().__init__(parent, name, fault)

    def start(self, fault="none"):
        if not self.installed:
            self.signer = Ed25519PrivateKey.generate()
            self.deployment_id = str(uuid.uuid4())
            self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            public = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            cfg = self.runtime / "d2a-public.json"
            cfg.write_bytes(canonical({"public_key":public.hex()}))
            os.chmod(cfg, 0o600); os.chown(cfg, d0.SUID, d0.SUID)
            with sqlite3.connect(self.runtime / "consumer.db") as db:
                db.executescript("""
                    ALTER TABLE demo_effects ADD COLUMN authorization_digest TEXT;
                    ALTER TABLE demo_effects ADD COLUMN ticket_digest TEXT;
                    INSERT INTO demo_configuration VALUES('synthetic-config-decoy',0,0);
                    CREATE TABLE d2_operations(operation_id TEXT PRIMARY KEY,envelope TEXT NOT NULL,
                        authorization_digest TEXT NOT NULL,uid INTEGER NOT NULL,ticket_digest TEXT,phase TEXT NOT NULL);
                    CREATE TABLE d2_meta(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL,
                        recovery INTEGER NOT NULL,deployment_id TEXT NOT NULL,boot_id TEXT NOT NULL);
                """)
                db.execute("INSERT INTO d2_meta VALUES(1,0,0,?,?)", (self.deployment_id,self.boot_id))
            self.installed = True
        self.process = subprocess.Popen(
            [sys.executable, str(HERE / "sql_service.py"), str(self.runtime), "--journal",str(self.journal),"--fault",fault],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
            user=d0.SUID,group=d0.SUID,extra_groups=[],umask=0o077)
        ready,_,_ = select.select([self.process.stdout],[],[],10)
        line = self.process.stdout.readline() if ready else ""
        if not line.startswith("READY "):
            if self.process.poll() is None:self.process.kill()
            _,err = self.process.communicate(timeout=5)
            raise RuntimeError("startup failed: "+err[:2000])

    def call(self, req, uid=d0.RUID, drop=False):
        result = super().call(req,uid,drop)
        if result.get("code","").startswith("OUTCOME_UNKNOWN") and "effect_status" not in result:
            result = {**result,"decision":"UNKNOWN","effect_status":"UNKNOWN",
                      "authority_status":"RECOVERY_REQUIRED","new_effect":None,"evidence_ref":None}
            self.calls[-1]["response"] = result
        self.calls[-1]["operation"] = req.get("operation",{})
        return result

    def observe(self):
        result = super().observe()
        with sqlite3.connect("file:"+str(self.runtime/"consumer.db")+"?mode=ro",uri=True) as db:
            result["operations"] = db.execute("SELECT operation_id,authorization_digest,uid,ticket_digest,phase FROM d2_operations ORDER BY operation_id").fetchall()
            result["effect_bindings"] = db.execute("SELECT operation_id,authorization_digest,ticket_digest FROM demo_effects ORDER BY event_id").fetchall()
            result["meta"] = db.execute("SELECT epoch,recovery,deployment_id,boot_id FROM d2_meta WHERE id=1").fetchone()
        return result

    def permit(self, rid="D2A_A", version=0, value=1, target="synthetic-config", ttl=30, **patch):
        status = self.call({"op":"status"})
        body = dict(schema=AUTH_SCHEMA,key_id=KEY_ID,namespace=NAMESPACE,deployment_id=self.deployment_id,
                    operation_id=rid,target=target,action="set_value",expected_version=version,value=value,
                    subject_uid=d0.RUID,subject_role="requester",policy_digest=status["policy"],context=CONTEXT,
                    authority_epoch=status["epoch"],boot_id=self.boot_id,not_before=clock(),not_after=clock()+ttl)
        body.update(patch)
        envelope = {"body":body,"signature":self.signer.sign(DOMAIN+canonical(body)).hex()}
        req = {"op":"execute","operation":{k:body[k] for k in OP_FIELDS},"authorization":envelope}
        self.public_permits.append(envelope)
        return req


def assert_committed(r):
    assert r["decision"] == "ACCEPTED" and r["effect_status"] == "COMMITTED_PROVEN" and r["new_effect"] is True,r


def assert_refused(r):
    assert r["decision"] == "REFUSED" and r["new_effect"] is False,r


def expected_two(f, a="D2A_A", b="D2A_B"):
    state=f.observe()
    assert ("synthetic-config",2,0) in state["configuration"],state
    assert state["effects"] == [(a,"synthetic-config",0,1,1),(b,"synthetic-config",1,2,0)],state
    assert len(state["effect_bindings"]) == 2 and all(len(r[1])==len(r[2])==64 for r in state["effect_bindings"]),state


def nominal(f):
    a=f.permit();assert_committed(f.call(a))
    b=f.permit("D2A_B",1,0);assert_committed(f.call(b))
    expected_two(f)
    for _ in range(10):
        for req in (a,b):
            r=f.call(req);assert r["decision"]=="REPLAY" and r["new_effect"] is False,r
    f.stop();f.start()
    assert f.call({"op":"status"})["authority_status"]=="LATCHED"
    for req in (a,b):
        r=f.call(req);assert r["effect_status"]=="COMMITTED_PROVEN" and r["new_effect"] is False,r
    expected_two(f)


def parameters(f):
    a=f.permit()
    for key,value in (("operation_id","OTHER"),("target","synthetic-config-decoy"),
                      ("expected_version",1),("value",0),("value",True)):
        req=copy.deepcopy(a);req["operation"][key]=value;assert_refused(f.call(req))
    assert_refused(f.call(a,d0.MUID))
    assert_refused(f.call(a,d0.OTHER))
    for op in ("prepare","deliver","finish"):
        assert_refused(f.call({"op":op}))
    assert not f.observe()["effects"]
    # Positive controls: these alternative SQL values and target are executable
    # with their own correct signed authorization, not hardcoded rejections.
    decoy=f.permit("DECOY",0,0,target="synthetic-config-decoy")
    assert_committed(f.call(decoy))
    assert_committed(f.call(a))
    assert_committed(f.call(f.permit("D2A_B",1,0)))
    assert len(f.observe()["effects"])==3


def signed_fields(f):
    a=f.permit()
    for key in a["authorization"]["body"]:
        req=copy.deepcopy(a);v=req["authorization"]["body"][key]
        req["authorization"]["body"][key]=v+1 if type(v) is int else v+"x"
        assert_refused(f.call(req))
    wrong=f.permit("WRONG_CONTEXT",context="OTHER")
    assert_refused(f.call(wrong))
    assert not f.observe()["effects"]
    assert_committed(f.call(a))
    assert_committed(f.call(f.permit("D2A_B",1,0)))
    expected_two(f)


def conflicts(f):
    early=f.permit("EARLY_B",1,0);assert_refused(f.call(early))
    a=f.permit();assert_committed(f.call(a))
    conflict=f.permit("D2A_A",1,0);assert_refused(f.call(conflict))
    assert_refused(f.call(early))
    assert_committed(f.call(f.permit("D2A_B",1,0)))
    expected_two(f)


def cut(f, after):
    a=f.permit();r=f.call(a)
    assert r["effect_status"]=="UNKNOWN" and r["new_effect"] is None,r
    assert f.process.wait(timeout=5)==73
    f.process.communicate(timeout=5)
    observed=f.observe()
    assert len(observed["effects"])==(1 if after else 0),observed
    f.start()
    history=f.call({"op":"inspect","operation_id":"D2A_A"})
    if after:
        assert history["effect_status"]=="COMMITTED_PROVEN" and history["new_effect"] is False,history
    else:
        assert history["effect_status"]=="UNKNOWN" and history["new_effect"] is None,history
    f.commission()
    if after:
        assert_committed(f.call(f.permit("D2A_B",1,0)))
        expected_two(f)
    else:
        assert_refused(f.call(a))
        assert_committed(f.call(f.permit("RECOVERY_A",0,1)))
        assert_committed(f.call(f.permit("RECOVERY_B",1,0)))
        expected_two(f,"RECOVERY_A","RECOVERY_B")


def latch(f):
    old=f.permit()
    f.call({"op":"fixture_conditions","healthy":False},d0.MUID)
    r=f.call(old);assert r["new_effect"] is not True,r
    f.call({"op":"fixture_conditions","healthy":True},d0.MUID)
    early=f.permit("QUARANTINED",0,1)
    for _ in range(10):assert f.call(early)["new_effect"] is not True
    assert not f.observe()["effects"]
    f.stop();f.start()
    assert f.call({"op":"status"})["authority_status"] in ("LATCHED","RECOVERY_REQUIRED")
    assert_refused(f.call({"op":"rearm_local","witness":{}}))
    assert f.call({"op":"rearm_local","witness":{}},d0.MUID)["code"].startswith("BLOCK_")
    f.commission()
    for req in (old,early):assert_refused(f.call(req))
    assert_refused(f.call(f.permit("STALE_GENERATION",authority_epoch=old["authorization"]["body"]["authority_epoch"])))
    # Fresh IDs only; the original A was quarantined, even after rearm.
    assert_committed(f.call(f.permit("FRESH_A",0,1)))
    assert_committed(f.call(f.permit("FRESH_B",1,0)))
    expected_two(f,"FRESH_A","FRESH_B")


def expired(f):
    req=f.permit("EXPIRED",ttl=2)
    time.sleep(3)
    assert_refused(f.call(req))
    assert not f.observe()["effects"]
    assert_committed(f.call(f.permit()))
    assert_committed(f.call(f.permit("D2A_B",1,0)))
    expected_two(f)


def campaign(out):
    if sys.platform!="linux" or os.geteuid()!=0:raise RuntimeError("NOT_RUN_ENVIRONMENT: Linux root controller required")
    for mapping in ("uid_map","gid_map"):
        ranges=[tuple(map(int,l.split())) for l in Path('/proc/self/'+mapping).read_text().splitlines()]
        if not all(any(start<=uid<start+length for start,_,length in ranges) for uid in (d0.SUID,d0.RUID,d0.MUID,d0.OTHER)):
            raise RuntimeError("NOT_RUN_ENVIRONMENT: test UIDs are not mapped")
    out.mkdir(parents=True,exist_ok=False)
    cases=[]
    with tempfile.TemporaryDirectory(prefix="fci-d2a-") as tmp:
        parent=Path(tmp);parent.chmod(0o755)
        for name,fn,fault in (("nominal",nominal,"none"),("params",parameters,"none"),
                              ("signed",signed_fields,"none"),("conflicts",conflicts,"none"),
                              ("I4",lambda f:cut(f,False),"I4"),("I5",lambda f:cut(f,True),"I5"),
                              ("latch",latch,"none"),("expiry",expired,"none")):
            f=None;case={"id":name,"status":"STARTED"};d0.save(out/(name+'.json'),case)
            try:
                f=Fixture(parent,name,fault);f.commission();fn(f)
                case.update(status="PASS_EXECUTED_SCOPED",final=f.observe())
            except BaseException as e:
                case.update(status="FAIL_EXECUTED",error_type=type(e).__name__,error=str(e))
                if f is not None:
                    try:case["failure_observed"]=f.observe()
                    except BaseException as observation_error:case["observation_error"]=type(observation_error).__name__
                raise
            finally:
                if f is not None:
                    case.update(calls=f.calls,peer_receipts=f.peer_receipts,public_permits=f.public_permits,
                                events=[json.loads(l) for l in f.journal.read_text().splitlines()])
                    f.close()
                d0.save(out/(name+'.json'),case)
            cases.append(case)
    paths=json.loads((HERE/'DEPENDENCIES.json').read_text())["files"]
    source_hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths}
    source_hashes.update({str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.is_file()})
    receipt={"schema":SCHEMA,"status":"PASS_EXECUTED_SCOPED","cases":cases,"source_sha256":source_hashes,
             "python":platform.python_version(),"controller_uid":os.geteuid(),"service_uid":d0.SUID,
             "requester_uid":d0.RUID,"maintainer_uid":d0.MUID,"scope":"FIRST_INTEGRATION_SUBSET",
             "contract_acceptance":"NOT_COMPLETE","baseline":"NOT_IMPLEMENTED","remaining_cuts":["I0","I1","I2","I3","I6"],
             "independent_third_party_replay":"NOT_ESTABLISHED","qualification":"HOLD/OPEN","NONLEAK_END_TO_END":False}
    d0.save(out/'RESULTS.json',receipt)
    print(json.dumps({"status":receipt["status"],"cases":len(cases),"contract_acceptance":"NOT_COMPLETE"}))


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    campaign(p.parse_args().output)
