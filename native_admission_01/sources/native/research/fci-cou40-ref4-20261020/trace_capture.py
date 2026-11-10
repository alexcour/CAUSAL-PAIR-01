"""Execute only the REF4 integrated-entry delta and capture every SQL prefix.

The seven scenarios and their operation inventories are fixed below before
execution. A root controller provisions disposable keys and launches genuine
non-root Service workers. The worker calls handle directly: a returned Python
dictionary is not an IPC delivery. No historical test suite is imported or run.

Snapshots use a separate consumer SQLite connection for durable state, and the
actual service connection only for uncommitted working state. Raw signed rows
are retained. Neither a copied decision function nor an expected result selects
the event kind; the recorded operation/hook determines that kind.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from integrated_service import (DEFAULT_REQUEST_ID, REFERENCE, REF3, VERSION,
                                IntegratedConsumer, IntegratedService, Recheck,
                                normal_revalidation)
from fci_hardened.fixture_setup import provision
from fci_hardened.service import CONTEXT, VERSION as REFERENCE_VERSION, clock
from fci_hardened.spend_ledger import ticket_digest
from fci_hardened.strict_json import canonical
from lifecycle import HOLD, fixture_rearm
from base01.authority import fixture_witness


SCENARIO_IDS = (
    "HEALTHY", "LATE_INVALID", "PROVIDER_EXCEPTION",
    "CUT_AFTER_RECHECK_PASS", "CUT_AFTER_RECHECK_DENIAL",
    "CUT_AFTER_PASS_COMMIT", "CUT_AFTER_DENIAL_COMMIT",
)
CUT_SCENARIOS = SCENARIO_IDS[3:]
CUT_EXIT = 73
EXPECTED_EVENT_COUNTS = {
    "HEALTHY": 28, "LATE_INVALID": 30, "PROVIDER_EXCEPTION": 25,
    "CUT_AFTER_RECHECK_PASS": 25, "CUT_AFTER_RECHECK_DENIAL": 25,
    "CUT_AFTER_PASS_COMMIT": 29, "CUT_AFTER_DENIAL_COMMIT": 26,
}
LOCAL_KEYS = {"instance", "target", "policy", "context", "mask", "epoch", "revision",
              "last_time", "level", "authority_floor"}
EFFECT_KEYS = {"request_id", "action", "target", "accepted_at", "effect_time",
               "consumer_revision", "ticket_digest"}
FENCE_KEYS = {"schema", "request_id", "scope", "ticket_digest", "consumer_revision",
              "sample_before", "checked_at", "flags", "source_revision", "decision"}
SCHEMA = "FCI-COU40-REF4-TRACE/1"


def operation_inventory():
    """Static planned events, not a list inferred from a successful execution."""
    initial = ["startup", "external_source_call:rearm_authority",
               "call_begin:rearm_local", "tx_begin:rearm", "tx_stage:rearm",
               "tx_commit:rearm", "call_return", "external_source_call:prepare",
               "call_begin:deliver", "tx_begin:receive", "tx_stage:receive",
               "tx_commit:receive", "call_return"]
    start_finish = ["call_begin:finish", "tx_begin:finish", "tx_stage:finish", "reserve",
                    "late_fence:0", "fence_remove"]
    full_finish = start_finish + ["late_fence:1", "tx_commit:finish", "call_return"]
    history = ["call_begin:finish", "tx_begin:finish", "tx_stage:finish", "tx_commit:finish", "call_return"]
    no_tx = ["call_begin:finish", "call_return"]
    rearm = ["call_begin:rearm_local", "tx_begin:rearm", "tx_stage:rearm", "tx_commit:rearm", "call_return"]
    result = {
        "HEALTHY": initial + full_finish + history + ["process_exit"],
        "LATE_INVALID": initial + full_finish + rearm + no_tx + ["process_exit"],
        "PROVIDER_EXCEPTION": initial + start_finish + ["provider_exception", "tx_rollback:finish", "call_return"] + no_tx + ["process_exit"],
    }
    for scenario in CUT_SCENARIOS:
        committed = scenario in ("CUT_AFTER_PASS_COMMIT", "CUT_AFTER_DENIAL_COMMIT")
        prefix = initial + start_finish + ["late_fence:1"]
        if committed:
            prefix += ["tx_commit:finish"]
        replay = history if scenario == "CUT_AFTER_PASS_COMMIT" else no_tx
        result[scenario] = prefix + ["process_exit", "startup"] + replay + ["process_exit"]
    if {key: len(value) for key, value in result.items()} != EXPECTED_EVENT_COUNTS:
        raise AssertionError("static inventory/count disagreement")
    return result


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_identities():
    files = [HERE / "integrated_service.py", HERE / "trace_capture.py", HERE / "test_integrated_service.py",
             REF3 / "composition_runtime.py", REFERENCE / "fci_hardened/service.py",
             REFERENCE / "fci_hardened/finalizing_consumer.py",
             REFERENCE / "fci_hardened/guarded_consumer.py",
             REFERENCE / "fci_hardened/spend_ledger.py",
             REFERENCE / "fci_hardened/fixture_setup.py",
             REFERENCE / "vendor/fci_repair05_life01/lifecycle.py"]
    return {str(path.relative_to(HERE.parents[1])): sha256(path) for path in files}


def environment():
    import cryptography
    return {"python": platform.python_version(), "python_executable": str(Path(sys.executable).resolve()),
            "sqlite": sqlite3.sqlite_version, "cryptography": cryptography.__version__,
            "platform": sys.platform, "uid": os.getuid(), "euid": os.geteuid(),
            "gid": os.getgid(), "egid": os.getegid(), "groups": os.getgroups(), "pid": os.getpid()}


def write_json(path, value):
    path = Path(path)
    with path.open("w", encoding="utf-8") as out:
        json.dump(value, out, sort_keys=True, indent=2, ensure_ascii=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.chmod(path, 0o644)


def write_final_capture(path, value):
    """Publish final bytes atomically, then reread and hash those exact bytes."""
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".pending")
    expected = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    with temporary.open("xb") as out:
        out.write(expected)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    actual = path.read_bytes()
    if actual != expected:
        raise AssertionError("final atomic capture differs on immediate byte readback")
    return hashlib.sha256(actual).hexdigest()


def signed_rows(connection, table, id_column):
    rows = []
    for ident, payload, signature in connection.execute(
            "SELECT " + id_column + ",payload,signature FROM " + table + " ORDER BY " + id_column):
        text = payload.decode("utf-8") if type(payload) is bytes else payload
        if type(text) is not str or type(signature) is not str:
            raise ValueError("unexpected SQL signed-row encoding")
        rows.append({id_column: ident, "payload_utf8": text, "payload_storage_type": type(payload).__name__,
                     "signature": signature, "decoded": json.loads(text)})
    return rows


def checked_local(value):
    if type(value) is not dict or set(value) != LOCAL_KEYS:
        raise ValueError("Local has not exactly ten fields")
    if any(type(value[key]) is not str for key in ("instance", "target", "policy", "context")):
        raise ValueError("Local identity type")
    if any(type(value[key]) is not int or value[key] < 0 for key in LOCAL_KEYS - {"instance", "target", "policy", "context"}):
        raise ValueError("Local natural-number domain")
    if value["mask"] >= 128 or value["level"] > 9:
        raise ValueError("Local bounds")
    return copy.deepcopy(value)


def read_consumer(connection, rid):
    raw = {table: signed_rows(connection, table, ident) for table, ident in (
        ("consumer", "id"), ("inbox", "request_id"), ("commit_fence", "request_id"), ("rearm_audit", "witness_id"))}
    if len(raw["consumer"]) != 1 or raw["consumer"][0]["id"] != 1:
        raise ValueError("consumer singleton")
    local = checked_local(raw["consumer"][0]["decoded"])
    scope = {key: local[key] for key in ("instance", "target", "policy", "context")}
    for table in ("inbox", "commit_fence"):
        if len(raw[table]) > 1 or any(row["request_id"] != rid for row in raw[table]):
            raise ValueError("capture is outside the one-ID domain")
    inbox = None
    ticket = None
    digest = None
    if raw["inbox"]:
        entry = raw["inbox"][0]["decoded"]
        if set(entry) != {"ticket", "status", "effect", "cancel", "delivery"} or entry["cancel"] is not None:
            raise ValueError("capture outside retained no-cancel inbox domain")
        ticket = entry["ticket"]
        token, receipt = ticket["token"]["body"], ticket["receipt"]["body"]
        if token["request_id"] != rid or receipt["request_id"] != rid:
            raise ValueError("raw ticket ID binding")
        if token["action"] != receipt["action"] or receipt["target"] != local["target"]:
            raise ValueError("raw ticket action/target binding")
        # All source scope fields are checked in the actual ticket, never
        # overwritten from a presumed order header.
        for key in ("instance", "policy", "context"):
            if token["authority"][key] != local[key] or receipt["authority_before"][key] != local[key]:
                raise ValueError("raw ticket scope binding")
        delivery = entry["delivery"]
        if set(delivery) != {"epoch", "policy", "context", "eligible"}:
            raise ValueError("delivery fields")
        if (delivery["policy"], delivery["context"]) != (local["policy"], local["context"]):
            raise ValueError("delivery scope")
        if type(delivery["eligible"]) is not bool or type(delivery["epoch"]) is not int:
            raise ValueError("delivery types")
        digest = ticket_digest(ticket)
        effect = entry["effect"]
        if effect is not None:
            if set(effect) != EFFECT_KEYS:
                raise ValueError("effect fields")
            if any(effect[key] != receipt[key] for key in ("request_id", "action", "target", "accepted_at")):
                raise ValueError("effect source identity binding")
            if effect["ticket_digest"] != digest:
                raise ValueError("effect digest binding")
        inbox = {"status": entry["status"], "delivery": copy.deepcopy(delivery),
                 "ticket_digest": digest, "effect": copy.deepcopy(effect)}
    fence = None
    if raw["commit_fence"]:
        fence = raw["commit_fence"][0]["decoded"]
        if set(fence) != FENCE_KEYS or fence["schema"] != "FCI-C004-SAMPLED/1":
            raise ValueError("fence fields")
        if fence["request_id"] != rid or fence["scope"] != scope or fence["ticket_digest"] != digest:
            raise ValueError("fence raw identity/scope/digest")
        fence = copy.deepcopy(fence)
    audit = []
    for row in raw["rearm_audit"]:
        value = row["decoded"]
        if set(value) != {"witness_digest", "before", "after"} or value["witness_digest"] != row["witness_id"]:
            raise ValueError("rearm audit identity")
        audit.append({"witness_digest": value["witness_digest"], "before": checked_local(value["before"]),
                      "after": checked_local(value["after"])})
    return {"local": local, "inbox": inbox, "fence": fence,
            "rearm_audit": sorted(audit, key=lambda value: value["witness_digest"])}, raw


def read_spend(runtime, rid, scope):
    connection = sqlite3.connect(str(Path(runtime) / "spend.db"), isolation_level=None)
    try:
        raw = {"ledger": signed_rows(connection, "ledger", "id")}
    finally:
        connection.close()
    if len(raw["ledger"]) != 1 or raw["ledger"][0]["id"] != 1:
        raise ValueError("ledger singleton")
    body = raw["ledger"][0]["decoded"]
    if set(body) != {"schema", "scope", "revision", "attempts"} or body["schema"] != "FCI-C003-SPEND/1":
        raise ValueError("ledger fields")
    if body["scope"] != scope or set(body["attempts"]) - {rid}:
        raise ValueError("ledger scope or one-ID binding")
    if type(body["revision"]) is not int or body["revision"] != len(body["attempts"]):
        raise ValueError("ledger revision")
    attempt = body["attempts"].get(rid)
    if attempt is not None and set(attempt) != {"ticket_digest", "kind", "consumer_revision"}:
        raise ValueError("attempt fields")
    return {"revision": body["revision"], "attempt": copy.deepcopy(attempt)}, raw


def snapshot(runtime, rid, service=None, response=None):
    # Each durable read is a genuinely distinct SQLite connection. During an
    # open transaction this reads the last committed rows, not self.db.
    connection = sqlite3.connect(str(Path(runtime) / "consumer.db"), isolation_level=None, timeout=5)
    try:
        durable, raw_durable = read_consumer(connection, rid)
    finally:
        connection.close()
    scope = {key: durable["local"][key] for key in ("instance", "target", "policy", "context")}
    spend, raw_spend = read_spend(runtime, rid, scope)
    working, raw_working = None, None
    if service is not None and service.consumer.db.in_transaction:
        working, raw_working = read_consumer(service.consumer.db, rid)
    for view in (durable, working):
        if view is not None and view["inbox"] is not None and spend["attempt"] is not None:
            if view["inbox"]["ticket_digest"] != spend["attempt"]["ticket_digest"]:
                raise ValueError("independent attempt raw digest mismatch")
    observed = {"durable": durable, "working": working, "spend": spend,
                "service_open": service is not None,
                "poisoned": bool(service.poisoned) if service is not None else None,
                "response": copy.deepcopy(response)}
    raw = {"durable": raw_durable, "working": raw_working, "spend": raw_spend,
           "durable_source": "DISTINCT_SQLITE_CONNECTION",
           "working_source": "LIVE_CONSUMER_CONNECTION_IN_TRANSACTION" if working is not None else None}
    return observed, raw


def event_label(row):
    kind, data = row["event"]["kind"], row["event"]["data"]
    if kind in ("call_begin", "external_source_call"):
        return kind + ":" + data["op"]
    if kind in ("tx_begin", "tx_stage", "tx_commit", "tx_rollback"):
        return kind + ":" + data["operation"]
    if kind == "late_fence":
        return kind + ":" + str(row["raw"]["index"])
    return kind


def load_journal(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def append_journal(path, row):
    with Path(path).open("a", encoding="utf-8") as out:
        out.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        out.flush()
        os.fsync(out.fileno())


class Journal:
    def __init__(self, spec, phase):
        self.spec, self.phase = spec, phase
        existing = load_journal(spec["journal"])
        self.index = len(existing)
        self.response = existing[-1]["observed"]["response"] if existing else None

    def emit(self, kind, data, raw, service):
        if kind in ("startup", "call_begin"):
            self.response = None
        observed, sql = snapshot(self.spec["runtime"], self.spec["request_id"], service, self.response)
        self.index += 1
        raw = dict(raw)
        raw.update(sql=sql, pid=os.getpid(), euid=os.geteuid(), utc=utc_now())
        cut = False
        if self.phase == "initial":
            if self.spec["scenario"] in ("CUT_AFTER_RECHECK_PASS", "CUT_AFTER_RECHECK_DENIAL"):
                cut = kind == "late_fence" and raw.get("index") == 1
            if self.spec["scenario"] in ("CUT_AFTER_PASS_COMMIT", "CUT_AFTER_DENIAL_COMMIT"):
                cut = kind == "tx_commit" and data.get("operation") == "finish"
        if cut:
            raw["next_instruction"] = "os._exit(73) after this journal fsync"
        row = {"event_id": self.spec["scenario"] + "/" + f"{self.index:03d}",
               "event": {"kind": kind, "data": copy.deepcopy(data)}, "observed": observed, "raw": raw}
        append_journal(self.spec["journal"], row)
        if cut:
            os._exit(CUT_EXIT)

    def call(self, service, uid, request):
        response = service.handle(uid, canonical(request))
        op = request["op"]
        if op in ("rearm_local", "deliver", "finish"):
            self.response = {"code": response["code"], "new_effect": response.get("new_effect")}
            self.emit("call_return", {}, {"source": "worker obtained actual IntegratedService.handle return",
                                          "code_origin": "PYTHON_HANDLE_RETURN_OBSERVED_BY_CALLER",
                                          "request": request, "result": response}, service)
        elif op in ("rearm_authority", "prepare"):
            self.emit("external_source_call", {"op": op},
                      {"source": "worker obtained actual source-operation handle return; outside consumer model",
                       "request": request, "result": response,
                       "authority_state": service.authority.state().__dict__,
                       "anchor_state": service.anchor._read().__dict__}, service)
        else:
            raise ValueError("unsupported chronological operation")
        return response


def fixture_factory(scenario):
    if scenario in ("HEALTHY", "CUT_AFTER_RECHECK_PASS", "CUT_AFTER_PASS_COMMIT"):
        return normal_revalidation
    def factory(clock_provider, conditions_provider):
        if scenario == "PROVIDER_EXCEPTION":
            def extra():
                raise OSError("REF4 trusted late condition provider deliberately unavailable")
        elif scenario == "LATE_INVALID":
            def extra():
                return (True, True, 0, True, True)
        else:
            def extra():
                return (False, True, True, True, True)
        return (Recheck("ref4_trusted_fixture_late", clock_provider, extra),)
    return factory


def worker(spec_path, phase):
    spec = json.loads(Path(spec_path).read_text())
    receipt_path = Path(spec["worker_receipts"][phase])
    receipt = {"schema": SCHEMA, "scenario": spec["scenario"], "phase": phase, "started_utc": utc_now(),
               "environment": environment(), "source_sha256": source_identities(), "status": "STARTED"}
    write_json(receipt_path, receipt)
    journal = Journal(spec, phase)
    service = None
    try:
        service = IntegratedService(Path(spec["runtime"]), request_id=spec["request_id"],
                                    event_hook=journal.emit, revalidation_factory=fixture_factory(spec["scenario"]))
        # Ancillary read-only identity check, recorded separately from the
        # modeled consumer-operation chronology. No socket is opened here.
        status = service.handle(spec["requester_uid"], canonical({"op": "status"}))
        if status.get("candidate") != VERSION or status.get("reference_candidate") != REFERENCE_VERSION:
            raise AssertionError("integrated/reference runtime identity")
        if type(service.consumer) is not IntegratedConsumer or service.consumer._revalidation_factory is None:
            raise AssertionError("consumer not installed by opening")
        receipt.update(status="OPENED", status_warmup=status,
                       service_class=type(service).__name__, consumer_class=type(service.consumer).__name__,
                       constructor="INHERITED_Service.__init___REAL_UID_AND_FLOCK",
                       owner_thread=service._owner_thread,
                       service_lock={"fd": service.lock_fd, "owner_uid": os.fstat(service.lock_fd).st_uid},
                       runtime_files={name: {"uid": (Path(spec["runtime"]) / name).stat().st_uid,
                                             "mode": oct((Path(spec["runtime"]) / name).stat().st_mode & 0o777)}
                                      for name in ("deployment.json", "policy.json", "policy-public.key", "keys.json",
                                                   "anchor.db", "replica.db", "consumer.db", "spend.db")},
                       no_consumer_replacement=True, no_finish_patch=True)
        write_json(receipt_path, receipt)
        if phase == "initial":
            # Witnesses are issued by the trusted disposable-fixture holder of
            # the actual keys. Their source-authority guarantees are external.
            keys = {key: bytes.fromhex(value) for key, value in
                    json.loads((Path(spec["runtime"]) / "keys.json").read_text()).items()}
            result = journal.call(service, spec["maintainer_uid"],
                                  {"op": "rearm_authority", "witness": fixture_witness(service.authority.state(), keys["rearm"], clock())})
            if result["code"] != "REARM_ACCEPTED":
                raise AssertionError("fixture source commissioning failed: " + result["code"])
            result = journal.call(service, spec["maintainer_uid"],
                                  {"op": "rearm_local", "witness": fixture_rearm(service.consumer._state(), keys["local_rearm"], clock())})
            if result["code"] != "REARM_LOCAL_ACCEPTED":
                raise AssertionError("fixture local commissioning failed: " + result["code"])
            prepared = journal.call(service, spec["requester_uid"],
                                    {"op": "prepare", "request_id": spec["request_id"], "action": "COAST"})
            if "ticket" not in prepared:
                raise AssertionError("fixture prepare missing actual ticket")
            delivered = journal.call(service, spec["requester_uid"], {"op": "deliver", "ticket": prepared["ticket"]})
            if delivered["code"] != "DELIVERED":
                raise AssertionError("fixture delivery unavailable")
            journal.call(service, spec["requester_uid"], {"op": "finish", "request_id": spec["request_id"]})
            if spec["scenario"] in CUT_SCENARIOS:
                raise AssertionError("planned process cut was not reached")
            if spec["scenario"] == "LATE_INVALID":
                journal.call(service, spec["maintainer_uid"],
                             {"op": "rearm_local", "witness": fixture_rearm(service.consumer._state(), keys["local_rearm"], clock())})
            journal.call(service, spec["requester_uid"], {"op": "finish", "request_id": spec["request_id"]})
        else:
            journal.call(service, spec["requester_uid"], {"op": "finish", "request_id": spec["request_id"]})
        receipt.update(status="RETURNED", completed_utc=utc_now())
        write_json(receipt_path, receipt)
        service.close()
        return 0
    except BaseException as error:
        receipt.update(status="FAILED", completed_utc=utc_now(), error_type=type(error).__name__,
                       error=str(error), traceback=traceback.format_exc())
        write_json(receipt_path, receipt)
        if service is not None:
            service.close()
        return 1


def order_from_events(events):
    candidates = [row["raw"]["result"]["ticket"] for row in events
                  if row["event"] == {"kind": "external_source_call", "data": {"op": "prepare"}}
                  and "ticket" in row["raw"].get("result", {})]
    if len(candidates) != 1:
        raise ValueError("exactly one actual source ticket required")
    ticket = candidates[0]
    token, receipt = ticket["token"]["body"], ticket["receipt"]["body"]
    source = receipt["authority_before"]
    # Check actual source fields before extracting the fixed model parameter.
    if token["request_id"] != receipt["request_id"] or token["action"] != receipt["action"]:
        raise ValueError("order/ticket identity")
    return {"instance": source["instance"], "target": receipt["target"], "policy": source["policy"],
            "context": source["context"], "request_id": receipt["request_id"],
            "ticket_digest": ticket_digest(ticket), "command": receipt["action"]["value"],
            "accepted": receipt["accepted_at"], "expiry": token["expires_at"], "hold": HOLD}, ticket


def controller(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    os.chmod(output, 0o755)
    if any((output / name).exists() for name in ("CAPTURES.json", "CAPTURE_EXECUTION.json")):
        raise FileExistsError("refusing to overwrite a prior execution receipt")
    planned = operation_inventory()
    inventory = {"schema": SCHEMA, "scenario_ids": list(SCENARIO_IDS), "expected_workers": 11,
                 "expected_events": 188, "expected_prefixes_including_initial": 195,
                 "expected_event_counts": EXPECTED_EVENT_COUNTS, "operation_sequences": planned,
                 "event_ids": {case: [case + "/" + f"{n:03d}" for n in range(1, count + 1)]
                               for case, count in EXPECTED_EVENT_COUNTS.items()}}
    write_json(output / "TRACE_INVENTORY.json", inventory)
    start = time.monotonic()
    execution = {"schema": SCHEMA, "status": "RUNNING", "started_utc": utc_now(),
                 "environment": environment(), "source_sha256": source_identities(),
                 "expected_scenarios": list(SCENARIO_IDS), "worker_processes": [],
                 "legacy_campaigns_executed": [], "errors": []}
    sys.path.insert(0, str(REFERENCE / "tests"))
    from os_preflight import preflight
    execution["preflight"] = preflight()  # read-only capability inventory, not an old test
    traces = []
    try:
        if execution["preflight"]["status"] != "AVAILABLE":
            raise RuntimeError("non-root service worker environment unavailable")
        service_uid, requester_uid, maintainer_uid = execution["preflight"]["uids"][:3]
        for scenario in SCENARIO_IDS:
            with tempfile.TemporaryDirectory(prefix="fci-ref4-") as temp:
                base = Path(temp)
                os.chmod(base, 0o755)
                runtime, _keys, _signer = provision(base / "fixture", service_uid, requester_uid, maintainer_uid)
                journal = base / "events.jsonl"
                journal.touch(mode=0o600)
                os.chown(journal, service_uid, service_uid)
                receipt_dir = base / "worker"
                receipt_dir.mkdir(mode=0o700)
                os.chown(receipt_dir, service_uid, service_uid)
                spec = {"scenario": scenario, "runtime": str(runtime), "request_id": DEFAULT_REQUEST_ID,
                        "requester_uid": requester_uid, "maintainer_uid": maintainer_uid,
                        "journal": str(journal), "worker_receipts": {
                            phase: str(receipt_dir / (phase + ".json")) for phase in ("initial", "restart")}}
                spec_path = base / "spec.json"
                write_json(spec_path, spec)
                initial, initial_sql = snapshot(runtime, DEFAULT_REQUEST_ID)
                if any((initial["durable"]["inbox"], initial["durable"]["fence"], initial["durable"]["rearm_audit"],
                        initial["spend"]["attempt"], initial["spend"]["revision"])):
                    raise AssertionError("provisioned initial consumer stores are not empty")
                case_processes = []
                phases = ("initial", "restart") if scenario in CUT_SCENARIOS else ("initial",)
                for phase in phases:
                    command = [str(Path(sys.executable).resolve()), "-I", str(HERE / "trace_capture.py"),
                               "--worker", str(spec_path), "--phase", phase]
                    process_start = time.monotonic()
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                               user=service_uid, group=service_uid, extra_groups=[], umask=0o077)
                    timed_out = False
                    try:
                        stdout, stderr = process.communicate(timeout=30)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        process.kill()
                        stdout, stderr = process.communicate(timeout=5)
                    expected_exit = CUT_EXIT if scenario in CUT_SCENARIOS and phase == "initial" else 0
                    try:
                        child = json.loads(Path(spec["worker_receipts"][phase]).read_text())
                    except (OSError, ValueError) as error:
                        child = {"status": "UNAVAILABLE", "read_error": type(error).__name__ + ": " + str(error)}
                    receipt = {"scenario": scenario, "phase": phase, "pid": process.pid,
                               "actual_exit_code": process.returncode, "expected_exit_code": expected_exit,
                               "timed_out": timed_out, "completed_utc": utc_now(),
                               "elapsed_seconds": round(time.monotonic() - process_start, 6),
                               "requested_service_uid": service_uid, "command": command,
                               "stdout": stdout, "stderr": stderr, "child": child}
                    execution["worker_processes"].append(receipt)
                    case_processes.append(receipt)
                    prior = load_journal(journal)
                    last_response = prior[-1]["observed"]["response"] if prior else None
                    stopped, stopped_sql = snapshot(runtime, DEFAULT_REQUEST_ID, response=last_response)
                    end = {"event_id": scenario + "/" + f"{len(prior)+1:03d}",
                           "event": {"kind": "process_exit", "data": {}}, "observed": stopped,
                           "raw": {"source": "controller waitpid followed by distinct SQLite readback",
                                   "pid": process.pid, "actual_exit_code": process.returncode,
                                   "phase": phase, "utc": utc_now(), "sql": stopped_sql}}
                    append_journal(journal, end)
                    if timed_out or process.returncode != expected_exit or child.get("status") == "UNAVAILABLE":
                        # Preserve all available evidence before refusing the
                        # planned inventory or any successful execution claim.
                        write_json(output / (scenario + "_PARTIAL.json"),
                                   {"initial": initial, "initial_sql": initial_sql,
                                    "events": load_journal(journal), "workers": case_processes})
                        raise AssertionError("unexpected worker termination: " + scenario + "/" + phase)
                events = load_journal(journal)
                order, ticket = order_from_events(events)
                trace = {"schema": SCHEMA, "id": scenario, "initial": initial, "order": order,
                         "events": events, "metadata": {"initial_origin": "SQL_READ_AFTER_PROVISION_BEFORE_FIRST_SERVICE_INIT",
                         "initial_sql": initial_sql, "raw_ticket": ticket, "source_sha256": execution["source_sha256"],
                         "worker_processes": case_processes, "response_boundary": "PYTHON_HANDLE_CALLER_ONLY_NO_SOCKET",
                         "policy": "ONE_FIXED_SIGNED_DISPOSABLE_POLICY", "entrypoint": VERSION,
                         "mac_cryptography_and_physical_guarantees": "NOT_ESTABLISHED_BY_TRACE_COMPARISON"}}
                traces.append(trace)
                # One immutable file per finished scenario prevents a later
                # aggregate write from being the only copy of that evidence.
                write_json(output / (scenario + "_TRACE.json"), trace)
                if [event_label(row) for row in events] != planned[scenario]:
                    raise AssertionError("planned operation inventory differs: " + scenario)
                if len(events) != EXPECTED_EVENT_COUNTS[scenario]:
                    raise AssertionError("planned event count differs: " + scenario)
                print(json.dumps({"scenario": scenario, "events": len(events), "workers": len(case_processes),
                                  "status": "CAPTURED_AWAITING_INDEPENDENT_COMPARISON"}), flush=True)
        # Publish the aggregate once after all scenarios, never by repeated
        # truncation as the running list grows. On a failed run the individual
        # completed trace files and partial evidence remain available.
        final_capture_sha = write_final_capture(output / "CAPTURES.json", traces)
        execution.update(status="EXECUTED_AWAITING_LEAN_COMPARISON", scenario_ids=[t["id"] for t in traces],
                         executed_scenarios=len(traces), executed_workers=len(execution["worker_processes"]),
                         observed_events=sum(len(t["events"]) for t in traces),
                         observed_prefixes_including_initial=sum(len(t["events"])+1 for t in traces),
                         capture_sha256=final_capture_sha,
                         capture_publication="ATOMIC_REPLACE_FSYNC_AND_EXACT_BYTE_READBACK",
                         individual_trace_sha256={case: sha256(output / (case + "_TRACE.json")) for case in SCENARIO_IDS})
    except BaseException as error:
        execution.update(status="FAILED_EXECUTION", error_type=type(error).__name__)
        execution["errors"].append({"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()})
    execution.update(completed_utc=utc_now(), elapsed_seconds=round(time.monotonic()-start, 6))
    write_json(output / "CAPTURE_EXECUTION.json", execution)
    print(json.dumps({key: execution.get(key) for key in ("status", "executed_scenarios", "executed_workers",
                                                        "observed_events", "elapsed_seconds", "errors")}), flush=True)
    return 0 if execution["status"] == "EXECUTED_AWAITING_LEAN_COMPARISON" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--phase", choices=("initial", "restart"), default="initial", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker is not None:
        return worker(args.worker, args.phase)
    if args.output is None:
        parser.error("--output is required")
    return controller(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
