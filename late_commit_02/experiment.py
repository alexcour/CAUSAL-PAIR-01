#!/usr/bin/env python3
"""LATE-COMMIT-02: actual localhost HTTP, SQLite effects, controlled scheduling.

The harness controls gates and measures effects. The recovery client sees only
HTTP responses. No Temporal SDK, production FCI, or external physical effect.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import sqlite3
import sys
import threading

K = "synthetic-operation-K"
ARCHITECTURES = ("check_before_call", "receiver_fence_only", "atomic_idempotency",
                 "fence_and_reconcile")
SCHEDULES = ("old_first", "old_after_fence", "recovery_first", "no_old_request")
FAULTS = ("none", "disable_fence", "disable_dedup", "ignore_prior_commit")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def database(path):
    db = sqlite3.connect(path, timeout=10)
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA synchronous=FULL")
    return db


class Receiver:
    def __init__(self, path, architecture, fault):
        self.path, self.architecture, self.fault = path, architecture, fault
        self.old_arrived = threading.Event()
        self.old_may_commit = threading.Event()
        self.recovery_arrived = threading.Event()
        self.recovery_may_commit = threading.Event()
        self.recovery_may_commit.set()
        self.trace_lock = threading.Lock()
        self.events = []
        db = database(path)
        db.executescript("""
            CREATE TABLE effects(id INTEGER PRIMARY KEY, k TEXT NOT NULL, attempt TEXT NOT NULL);
            CREATE TABLE receipts(k TEXT PRIMARY KEY, effect_id INTEGER NOT NULL);
            CREATE TABLE epochs(k TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
        """)
        db.execute("INSERT INTO epochs VALUES (?, 0)", (K,))
        db.commit()
        db.close()

    def record(self, event, **values):
        with self.trace_lock:
            self.events.append({"seq": len(self.events) + 1, "event": event, **values})

    def lookup(self):
        db = database(self.path)
        try:
            prior = db.execute("SELECT id FROM effects WHERE k=? ORDER BY id LIMIT 1", (K,)).fetchone()
        finally:
            db.close()
        answer = {"state": "COMMITTED", "result": prior[0]} if prior else {"state": "NOT_FOUND"}
        self.record("lookup", **answer)
        return answer

    def transaction(self, endpoint, payload):
        attempt = payload.get("attempt", "recovery")
        db = database(self.path)
        event, status, answer = None, 200, None
        try:
            db.execute("BEGIN IMMEDIATE")
            epoch = db.execute("SELECT epoch FROM epochs WHERE k=?", (K,)).fetchone()[0]
            if endpoint in ("/advance", "/recover"):
                require(self.architecture in ("receiver_fence_only", "fence_and_reconcile"),
                        "unsupported fencing endpoint")
                epoch += 1
                db.execute("UPDATE epochs SET epoch=? WHERE k=?", (epoch, K))
                if endpoint == "/advance":
                    answer, event = {"epoch": epoch}, "fence_advanced"
                else:
                    require(self.architecture == "fence_and_reconcile", "unsupported recovery endpoint")
                    prior = db.execute("SELECT id FROM effects WHERE k=? ORDER BY id LIMIT 1", (K,)).fetchone()
                    if prior and self.fault != "ignore_prior_commit":
                        answer, event = {"state": "REUSED", "result": prior[0], "epoch": epoch}, "prior_reconciled"
            if answer is None:
                fenced = self.architecture in ("receiver_fence_only", "fence_and_reconcile")
                # /recover increments the epoch and performs the recovery effect in
                # THIS transaction; /execute must present the current epoch.
                if (endpoint == "/execute" and fenced and self.fault != "disable_fence"
                        and payload["epoch"] != epoch):
                    answer, event, status = {"state": "STALE"}, "stale_rejected", 409
                elif self.architecture == "atomic_idempotency" and self.fault != "disable_dedup":
                    prior = db.execute("SELECT effect_id FROM receipts WHERE k=?", (K,)).fetchone()
                    if prior:
                        answer, event = {"state": "REUSED", "result": prior[0]}, "receipt_reused"
                if answer is None:
                    cursor = db.execute("INSERT INTO effects(k,attempt) VALUES (?,?)", (K, attempt))
                    effect_id = cursor.lastrowid
                    if self.architecture == "atomic_idempotency" and self.fault != "disable_dedup":
                        db.execute("INSERT INTO receipts VALUES (?,?)", (K, effect_id))
                    answer, event = {"state": "COMMITTED", "result": effect_id}, "effect_committed"
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        self.record(event, attempt=attempt, endpoint=endpoint, **answer)
        return status, answer


def handler_for(receiver):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send_json(self, status, body):
            content = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self):
            if self.path != "/lookup":
                return self.send_json(404, {"error": "unknown endpoint"})
            receiver.record("http_arrival", method="GET", endpoint=self.path)
            self.send_json(200, receiver.lookup())

        def do_POST(self):
            try:
                require(self.path in ("/execute", "/advance", "/recover"), "unknown endpoint")
                length = int(self.headers["Content-Length"])
                require(0 < length < 4096, "invalid request length")
                payload = json.loads(self.rfile.read(length))
                require(payload.get("k") == K, "operation mismatch")
                receiver.record("http_arrival", method="POST", endpoint=self.path,
                                attempt=payload.get("attempt", "recovery"))
                if payload.get("attempt") == "old":
                    receiver.old_arrived.set()
                    require(receiver.old_may_commit.wait(10), "old request gate timed out")
                elif self.path == "/execute":
                    receiver.recovery_arrived.set()
                    require(receiver.recovery_may_commit.wait(10), "recovery request gate timed out")
                status, answer = receiver.transaction(self.path, payload)
                self.send_json(status, answer)
            except Exception as exc:
                receiver.record("receiver_error", message=str(exc))
                self.send_json(500, {"error": str(exc)})
    return Handler


def request(port, method, endpoint, payload=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        data = json.dumps(payload).encode() if payload is not None else None
        connection.request(method, endpoint, body=data, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        result = {"http_status": response.status, "body": json.loads(response.read())}
        require(response.status in (200, 409), "HTTP failure: " + str(result))
        return result
    finally:
        connection.close()


def recover(port, architecture, lookup):
    """Controller interface: only actual HTTP responses, never harness events."""
    require(lookup["body"]["state"] == "NOT_FOUND", "this experiment requires an absent lookup")
    payload = {"k": K, "attempt": "recovery", "epoch": 0}
    if architecture == "receiver_fence_only":
        advanced = request(port, "POST", "/advance", payload)
        payload["epoch"] = advanced["body"]["epoch"]
    if architecture == "fence_and_reconcile":
        return request(port, "POST", "/recover", payload)
    return request(port, "POST", "/execute", payload)


def run_case(root, architecture, schedule, fault):
    require(schedule != "old_after_fence" or architecture == "receiver_fence_only",
            "old_after_fence applies only to the separate-fence architecture")
    folder = root / (architecture + "__" + schedule)
    folder.mkdir()
    receiver = Receiver(folder / "receiver.sqlite", architecture, fault)
    if schedule == "old_after_fence":
        receiver.recovery_may_commit.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(receiver))
    server.daemon_threads = True
    server_thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01))
    server_thread.start()
    port = server.server_address[1]
    pool = ThreadPoolExecutor(max_workers=2)
    old_response = None
    try:
        old_future = None
        if schedule != "no_old_request":
            old_future = pool.submit(request, port, "POST", "/execute",
                                     {"k": K, "attempt": "old", "epoch": 0})
            require(receiver.old_arrived.wait(10), "old request did not arrive")
        lookup = request(port, "GET", "/lookup")
        require(lookup == {"http_status": 200, "body": {"state": "NOT_FOUND"}}, "unexpected lookup")
        if schedule == "old_first":
            receiver.old_may_commit.set()
            # Harness observes this response; the recovery controller does NOT.
            old_response = old_future.result(timeout=15)
        if schedule == "old_after_fence":
            recovery_future = pool.submit(recover, port, architecture, lookup)
            require(receiver.recovery_arrived.wait(10), "recovery did not reach the receiver")
            receiver.old_may_commit.set()
            old_response = old_future.result(timeout=15)
            receiver.recovery_may_commit.set()
            recovery_response = recovery_future.result(timeout=15)
        else:
            recovery_response = recover(port, architecture, lookup)
        if schedule == "recovery_first":
            receiver.old_may_commit.set()
            old_response = old_future.result(timeout=15)
    finally:
        receiver.old_may_commit.set()
        receiver.recovery_may_commit.set()
        pool.shutdown(wait=True)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
        require(not server_thread.is_alive(), "server did not shut down")
    db = sqlite3.connect(folder / "receiver.sqlite")
    try:
        effects = db.execute("SELECT id,k,attempt FROM effects ORDER BY id").fetchall()
        receipts = db.execute("SELECT k,effect_id FROM receipts ORDER BY k").fetchall()
        epochs = db.execute("SELECT k,epoch FROM epochs ORDER BY k").fetchall()
        require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "database integrity")
    finally:
        db.close()
    expected = 1
    if schedule != "no_old_request" and architecture == "check_before_call":
        expected = 2
    if schedule == "old_first" and architecture == "receiver_fence_only":
        expected = 2
    public_observation = {"k": K, "authorization": "valid", "lookup": lookup}
    row = {"architecture": architecture, "schedule": schedule, "fault": fault,
           "controller_observation": public_observation,
           "observation_sha256": hashlib.sha256(json.dumps(public_observation, sort_keys=True).encode()).hexdigest(),
           "old_response": old_response, "recovery_response": recovery_response,
           "effects": effects, "receipts": receipts, "epochs": epochs,
           "final_effects": len(effects), "expected_effects": expected,
           "http_arrivals": sum(e["event"] == "http_arrival" for e in receiver.events),
           "events": receiver.events, "at_most_one_effect": len(effects) <= 1, "outcome_matches": len(effects) == expected}
    (folder / "trace.json").write_text(json.dumps(row, indent=2) + "\n")
    require(not any(e["event"] == "receiver_error" for e in receiver.events), "receiver error")
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--architecture", choices=ARCHITECTURES)
    parser.add_argument("--schedule", choices=SCHEDULES)
    parser.add_argument("--fault", choices=FAULTS, default="none")
    args = parser.parse_args()
    require(not args.out.exists(), "use a fresh output directory")
    args.out.mkdir(parents=True)
    architectures = (args.architecture,) if args.architecture else ARCHITECTURES
    schedules = (args.schedule,) if args.schedule else SCHEDULES
    require(args.schedule != "old_after_fence" or args.architecture == "receiver_fence_only",
            "select --architecture receiver_fence_only for --schedule old_after_fence")
    cases = [run_case(args.out, a, s, args.fault) for a in architectures for s in schedules
             if s != "old_after_fence" or a == "receiver_fence_only"]
    passed = all(c["outcome_matches"] for c in cases)
    report = {"experiment": "LATE-COMMIT-02", "status": "PASS_EXPECTED_OUTCOMES" if passed else "EXPECTED_OUTCOME_FAILURE",
              "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                              "optimize": sys.flags.optimize}, "cases": cases}
    (args.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "cases": len(cases)}))
    return 0 if passed else 3


if __name__ == "__main__":
    sys.exit(main())
