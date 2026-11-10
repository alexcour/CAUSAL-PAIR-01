"""Separate checker of the D0 observations, not a scientific independent review."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path

EXPECTED={"NOMINAL_AND_REPLAY":1,"ALTERED_OPERATION_AND_ROLES":0,"TAMPERED_TICKET":1,
          "LATCH_RESTART_AND_REARM":0,"RESPONSE_NOT_READ":1,"CUT_BEFORE_COMMIT":0,
          "CUT_AFTER_COMMIT":1,"REQUESTER_WRITE_DENIED":1,"EXPIRED_PERMISSION":0}


def verify(receipt, root):
    if receipt["status"] != "PASS_EXECUTED_SCOPED" or receipt["case_count"] != len(EXPECTED):
        raise ValueError("incomplete execution")
    cases={c["id"]:c for c in receipt["cases"]}
    if set(cases)!=set(EXPECTED) or len(receipt["cases"])!=len(EXPECTED):
        raise ValueError("scenario identity/duplicate")
    for path,expected in receipt["source_sha256"].items():
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("source path")
        if hashlib.sha256((root/path).read_bytes()).hexdigest()!=expected:
            raise ValueError("execution source changed: "+path)
    if (receipt["controller_uid"],receipt["service_uid"],receipt["requester_uid"],receipt["maintainer_uid"])!=(0,61051,61052,61053):
        raise ValueError("process-role provenance")
    if receipt["reference_commit"]!="7a0784a4dc8d9953487ebeb54bd42df834d40eb4":
        raise ValueError("reference version")
    if receipt["global_claims"]!={"qualification":"HOLD/OPEN","NONLEAK_END_TO_END":False,
                                "physical_tests":"NOT_RUN","full_P01_P14":"NOT_COMPLETE"}:
        raise ValueError("scope promotion")
    for name,count in EXPECTED.items():
        c=cases[name]
        if c["status"]!="PASS_EXECUTED_SCOPED":raise ValueError("case status")
        if c["initial"]["configuration"] != [["synthetic-config",0,0]] or c["initial"]["effects"]:
            raise ValueError("unclean target")
        if c["final"]["configuration"] != [["synthetic-config",count,count]]:
            raise ValueError("actual target value/version")
        if len(c["final"]["effects"]) != count:
            raise ValueError("actual target effect count")
        if count and c["final"]["effects"] != [["CFG001","synthetic-config",0,1,1]]:
            raise ValueError("effect identity")
        if not c["events"] or any(e["uid"]!=61051 for e in c["events"]):
            raise ValueError("real service UID")
        if not c["peer_receipts"] or any(p["peer_uid"] not in (61052,61053,61054) for p in c["peer_receipts"]):
            raise ValueError("real requester/maintainer UIDs")
    latch=cases["LATCH_RESTART_AND_REARM"]
    if latch["final"]["mask"] != 0:raise ValueError("explicit rearm did not complete")
    if not any(x["response"].get("code")=="REARM_LOCAL_ACCEPTED" for x in latch["calls"]):
        raise ValueError("no explicit rearm call")
    loss=cases["RESPONSE_NOT_READ"]["calls"]
    if not any(x["response"].get("code")=="OUTCOME_UNKNOWN_CLIENT_RESPONSE_NOT_READ"
               and x["response"].get("new_effect","absent") is None for x in loss):
        raise ValueError("lost reply collapsed to no-effect")
    for name in ("CUT_BEFORE_COMMIT","CUT_AFTER_COMMIT"):
        if not any(e["kind"]=="tx_stage" and e.get("target_staged") for e in cases[name]["events"]):
            raise ValueError("target write boundary never reached")
    return {"status":"PASS_EXECUTED_SCOPED","cases":len(EXPECTED),
            "qualification":"HOLD/OPEN","physical_tests":"NOT_RUN"}


def main():
    ap=argparse.ArgumentParser();ap.add_argument("results",type=Path);ap.add_argument("--root",type=Path,
                  default=Path(__file__).resolve().parents[2]);ap.add_argument("--negative-checks",action="store_true")
    args=ap.parse_args();receipt=json.loads(args.results.read_text());result=verify(receipt,args.root)
    if args.negative_checks:
        rejected=[]
        for name,mutate in (
            ("false_effect",lambda r:r["cases"][0]["final"].update(configuration=[["synthetic-config",0,0]])),
            ("duplicate_effect",lambda r:r["cases"][0]["final"]["effects"].append(["CFG001","synthetic-config",0,1,1])),
            ("false_global_qualification",lambda r:r["global_claims"].update(NONLEAK_END_TO_END=True))):
            changed=copy.deepcopy(receipt);mutate(changed)
            try:verify(changed,args.root)
            except ValueError:rejected.append(name)
            else:raise AssertionError("bad evidence accepted: "+name)
        result["negative_evidence_checks_rejected"]=rejected
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":main()
