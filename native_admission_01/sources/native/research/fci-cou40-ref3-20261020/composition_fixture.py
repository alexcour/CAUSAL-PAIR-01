"""Disposable in-process fixture helpers, not an installed service path."""
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

from composition_runtime import CompositionConsumer, Recheck, RUNTIME
sys.path.insert(0, str(RUNTIME / "tests"))
from test_service_components import ComponentHarness

OK = (True,) * 5
BAD_RUNTIME = (False, True, True, True, True)


class CompositionHarness(ComponentHarness):
    def start(self):
        super().start()
        s = self.component
        before = s.consumer._state()
        s.consumer.close()
        k = self.keys
        # Normal opening records STARTUP. It is deliberately not worker attach.
        s.consumer = CompositionConsumer(
            self.runtime / "consumer.db", k["effect"], k["token"], k["receipt"],
            k["local_rearm"], ledger=s.spend)
        self.composition_startup = {
            "operation": "startup", "before": asdict(before), "input": {},
            "after_attested": asdict(s.consumer._state()), "code": "STARTUP_RECORDED",
            "code_origin": "NORMALIZED_CONSTRUCTOR_SUCCESS",
            "durability": "COMMITTED_READBACK",
            "scope": "candidate normal constructor following fixture Service opening; not a new service deployment"}


def fixed_check(name, raw=OK, first=100, last=100):
    times = iter((first, last))
    return Recheck(name, lambda: next(times), lambda: raw)


def finish_through_service(h, rid, checks=(), observer_hook=None):
    """Trusted test wiring only; Service's client request gets no new fields."""
    c = h.component.consumer
    original = c.finish
    def invoke(request_id, anchor, clock, conditions, hook=None):
        selected_hook = observer_hook if observer_hook is not None else hook
        return original(request_id, anchor, clock, conditions, selected_hook, rechecks=checks)
    with patch.object(c, "finish", side_effect=invoke):
        return h.call({"op": "finish", "request_id": rid})


def durable(h, rid=None):
    with sqlite3.connect(h.runtime / "consumer.db") as db:
        state = json.loads(db.execute("SELECT payload FROM consumer WHERE id=1").fetchone()[0])
        entry_row = (db.execute("SELECT payload,signature FROM inbox WHERE request_id=?", (rid,)).fetchone()
                     if rid is not None else None)
        fence_row = (db.execute("SELECT payload,signature FROM commit_fence WHERE request_id=?", (rid,)).fetchone()
                     if rid is not None else None)
    with sqlite3.connect(h.runtime / "spend.db") as db:
        ledger = json.loads(db.execute("SELECT payload FROM ledger WHERE id=1").fetchone()[0])
    return {"state": state, "entry": json.loads(entry_row[0]) if entry_row else None,
            "fence": json.loads(fence_row[0]) if fence_row else None,
            "fence_signature": fence_row[1] if fence_row else None,
            "reservation": ledger["attempts"].get(rid) if rid is not None else None,
            "reservation_ids": sorted(ledger["attempts"]), "durability": "INDEPENDENT_SQLITE_CONNECTIONS"}
