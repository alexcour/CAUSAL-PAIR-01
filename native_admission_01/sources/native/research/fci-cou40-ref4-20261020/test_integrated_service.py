"""Five tests of the newly executed REF4 captures; no worker is rerun.

These checks consume the signed-row evidence, process receipts and observed
handle returns. The separate Lean fold comparison is performed by run_ref4.py.
No reference campaign, service or decision oracle is imported by this module.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import sqlite3
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
SCENARIO_IDS = ("HEALTHY", "LATE_INVALID", "PROVIDER_EXCEPTION", "CUT_AFTER_RECHECK_PASS",
                "CUT_AFTER_RECHECK_DENIAL", "CUT_AFTER_PASS_COMMIT", "CUT_AFTER_DENIAL_COMMIT")
EXPECTED_TEST_METHODS = (
    "test_01_real_integrated_open_and_healthy_history",
    "test_02_late_invalid_rearm_retains_same_id_fence",
    "test_03_real_provider_exception_and_poison",
    "test_04_process_cuts_after_second_revalidation",
    "test_05_process_cuts_after_integrated_commit",
)
CAPTURE_DIR = None
OBSERVATIONS = []


def rows(trace, kind, operation=None):
    return [row for row in trace["events"] if row["event"]["kind"] == kind
            and (operation is None or row["event"]["data"].get("operation") == operation)]


def returned(trace, op):
    return [row for row in rows(trace, "call_return") if row["raw"]["request"]["op"] == op]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class IntegratedCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.traces = {trace["id"]: trace for trace in json.loads((CAPTURE_DIR / "CAPTURES.json").read_text())}
        cls.execution = json.loads((CAPTURE_DIR / "CAPTURE_EXECUTION.json").read_text())
        if set(cls.traces) != set(SCENARIO_IDS):
            raise AssertionError("incomplete seven-scenario capture")
        if cls.execution["status"] != "EXECUTED_AWAITING_LEAN_COMPARISON":
            raise AssertionError("capture campaign did not complete")
        if cls.execution["capture_sha256"] != sha256(CAPTURE_DIR / "CAPTURES.json"):
            raise AssertionError("captured evidence changed after execution receipt")
        for filename, expected in cls.execution["source_sha256"].items():
            if sha256(HERE.parents[1] / filename) != expected:
                raise AssertionError("execution/source hash mismatch: " + filename)

    def observe_case(self, case, findings):
        OBSERVATIONS.append({"case": case, "status": "PASS_EXECUTED_SCOPED", "findings": findings})

    def assert_real_rows(self, event):
        for view_name in ("durable", "working"):
            view = event["observed"][view_name]
            raw = event["raw"]["sql"][view_name]
            if view is None:
                self.assertIsNone(raw)
                continue
            self.assertEqual(view["local"], raw["consumer"][0]["decoded"])
            self.assertEqual(raw["consumer"][0]["decoded"], json.loads(raw["consumer"][0]["payload_utf8"]))
            self.assertEqual(len(view["local"]), 10)
            if view["inbox"] is None:
                self.assertEqual(raw["inbox"], [])
            else:
                entry = raw["inbox"][0]["decoded"]
                self.assertEqual(entry, json.loads(raw["inbox"][0]["payload_utf8"]))
                self.assertIsNone(entry["cancel"])
                for key in ("status", "delivery", "effect"):
                    self.assertEqual(view["inbox"][key], entry[key])
            self.assertEqual(view["fence"], raw["commit_fence"][0]["decoded"] if raw["commit_fence"] else None)
        self.assertEqual(event["raw"]["sql"]["durable_source"], "DISTINCT_SQLITE_CONNECTION")

    def test_01_real_integrated_open_and_healthy_history(self):
        case = "HEALTHY"
        trace = self.traces[case]
        self.assertFalse(trace["initial"]["service_open"])
        self.assertIsNone(trace["initial"]["poisoned"])
        initial = trace["initial"]["durable"]["local"]
        startup = rows(trace, "startup")[0]
        actual = startup["observed"]["durable"]["local"]
        self.assertEqual(actual["mask"], initial["mask"] | 32)
        self.assertEqual(actual["revision"], initial["revision"] + 1)
        self.assertEqual(actual["epoch"], initial["epoch"] + 1)
        self.assertEqual(startup["raw"]["code_origin"], "NO_CONSTRUCTOR_RETURN_CODE")
        for receipt in self.execution["worker_processes"]:
            child = receipt["child"]
            self.assertEqual(child["environment"]["euid"], receipt["requested_service_uid"])
            self.assertNotEqual(child["environment"]["euid"], 0)
            self.assertEqual(child["environment"]["pid"], receipt["pid"])
            self.assertEqual(child["service_class"], "IntegratedService")
            self.assertEqual(child["consumer_class"], "IntegratedConsumer")
            self.assertTrue(child["no_consumer_replacement"])
            self.assertTrue(child["no_finish_patch"])
            self.assertEqual(child["status_warmup"]["candidate"], "FCI-COU40-REF4-INTEGRATED/1")
            self.assertNotEqual(child["status_warmup"]["reference_candidate"], child["status_warmup"]["candidate"])
            for attributes in child["runtime_files"].values():
                self.assertEqual(attributes["uid"], receipt["requested_service_uid"])
                self.assertEqual(attributes["mode"], "0o600")
        finish_returns = returned(trace, "finish")
        self.assertEqual([row["observed"]["response"] for row in finish_returns],
                         [{"code": "EFFECT_COMMITTED", "new_effect": True},
                          {"code": "ACK_EFFECT_HISTORY", "new_effect": False}])
        finalizers = rows(trace, "late_fence")
        self.assertEqual([row["raw"]["index"] for row in finalizers], [0, 1])
        for row in finalizers:
            self.assert_real_rows(row)
            self.assertEqual(row["observed"]["durable"]["local"]["level"], 0)
            self.assertEqual(row["observed"]["working"]["local"]["level"], 1)
            self.assertEqual(row["observed"]["working"]["fence"]["decision"], "COMMIT_FENCE_PASS")
        self.assertEqual(finish_returns[0]["observed"]["durable"], finish_returns[1]["observed"]["durable"])
        self.assertEqual(finish_returns[0]["observed"]["spend"], finish_returns[1]["observed"]["spend"])
        self.assertEqual(len(rows(trace, "reserve")), 1)
        self.observe_case(case, ["real constructor with dedicated UID and original lifetime lock",
                                 "two integrated sampled PASS fences before one durable effect",
                                 "same-ID history has no new effect or reservation"])

    def test_02_late_invalid_rearm_retains_same_id_fence(self):
        case = "LATE_INVALID"
        trace = self.traces[case]
        fences = rows(trace, "late_fence")
        self.assertEqual(fences[0]["observed"]["working"]["fence"]["decision"], "COMMIT_FENCE_PASS")
        denied = fences[1]
        self.assert_real_rows(denied)
        self.assertEqual(denied["raw"]["normalization_observations"][-1]["diagnostic"], "INPUT_INVALID")
        self.assertEqual(denied["raw"]["normalization_observations"][-1]["reason"], "FLAGS_BOOL")
        self.assertEqual(denied["event"]["data"]["flags"], [False]*5)
        self.assertEqual(denied["observed"]["working"]["local"]["mask"], 31)
        self.assertEqual(denied["observed"]["working"]["local"]["level"], 0)
        self.assertEqual(denied["observed"]["working"]["inbox"]["status"], "PENDING")
        self.assertFalse(denied["observed"]["working"]["inbox"]["delivery"]["eligible"])
        committed = rows(trace, "tx_commit", "finish")[0]
        self.assertEqual(committed["observed"]["durable"]["local"]["mask"], 31)
        self.assertEqual(committed["observed"]["durable"]["local"]["level"], 0)
        self.assertIsNone(committed["observed"]["durable"]["inbox"]["effect"])
        rearmed = returned(trace, "rearm_local")[-1]
        self.assertEqual(rearmed["observed"]["response"]["code"], "REARM_LOCAL_ACCEPTED")
        self.assertEqual(rearmed["observed"]["durable"]["local"]["mask"], 0)
        self.assertFalse(rearmed["observed"]["durable"]["inbox"]["delivery"]["eligible"])
        self.assertEqual(rearmed["observed"]["durable"]["fence"], committed["observed"]["durable"]["fence"])
        self.assertEqual(rearmed["observed"]["spend"], committed["observed"]["spend"])
        self.assertEqual(returned(trace, "finish")[-1]["observed"]["response"],
                         {"code": "BLOCK_COMMIT_FENCE_HISTORY", "new_effect": False})
        self.assertEqual(len(rows(trace, "reserve")), 1)
        self.observe_case(case, ["malformed trusted late input normalized by REF3 to five false flags",
                                 "mask31 denial is durable at consumer COMMIT",
                                 "full authenticated local rearm clears latch but retains ineligibility/fence/spend"])

    def test_03_real_provider_exception_and_poison(self):
        case = "PROVIDER_EXCEPTION"
        trace = self.traces[case]
        failed = rows(trace, "provider_exception")
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["raw"]["exception_type"], "OSError")
        self.assertFalse(failed[0]["observed"]["poisoned"])
        self.assertEqual(failed[0]["observed"]["working"]["local"]["level"], 1)
        self.assertIsNone(failed[0]["observed"]["working"]["fence"])
        rollback = rows(trace, "tx_rollback", "finish")[0]
        self.assertTrue(rollback["raw"]["consumer_sql_rows_equal_to_begin"])
        self.assert_real_rows(rollback)
        self.assertIsNone(rollback["observed"]["working"])
        self.assertEqual(rollback["observed"]["durable"]["local"]["level"], 0)
        self.assertEqual(rollback["observed"]["durable"]["inbox"]["status"], "PENDING")
        self.assertIsNone(rollback["observed"]["durable"]["fence"])
        self.assertEqual(rollback["observed"]["spend"]["revision"], 1)
        self.assertFalse(rollback["observed"]["poisoned"])
        replies = returned(trace, "finish")
        self.assertEqual([row["observed"]["response"] for row in replies],
                         [{"code": "OUTCOME_UNKNOWN_SERVICE_FAULT", "new_effect": None},
                          {"code": "BLOCK_SERVICE_FAULT", "new_effect": None}])
        self.assertTrue(replies[0]["observed"]["poisoned"])
        self.assertEqual(replies[0]["observed"]["durable"], replies[1]["observed"]["durable"])
        self.assertEqual(rows(trace, "tx_commit", "finish"), [])
        self.observe_case(case, ["real provider OSError at new integrated recheck",
                                 "consumer rollback independently reread while spend remains committed",
                                 "UNKNOWN returned, service poisoned, subsequent finish blocked without transaction"])

    def test_04_process_cuts_after_second_revalidation(self):
        for case in ("CUT_AFTER_RECHECK_PASS", "CUT_AFTER_RECHECK_DENIAL"):
            with self.subTest(case=case):
                trace = self.traces[case]
                last = rows(trace, "late_fence")[-1]
                self.assertEqual(last["raw"]["index"], 1)
                self.assertIn("os._exit(73)", last["raw"]["next_instruction"])
                self.assertEqual(len(rows(trace, "reserve")), 1)
                self.assertEqual(rows(trace, "tx_commit", "finish"), [])
                exits = rows(trace, "process_exit")
                self.assertEqual(exits[0]["raw"]["actual_exit_code"], 73)
                self.assertIsNone(exits[0]["observed"]["response"])
                self.assertIsNone(exits[0]["observed"]["working"])
                self.assertIsNone(exits[0]["observed"]["poisoned"])
                self.assertEqual(exits[0]["observed"]["durable"]["local"]["level"], 0)
                self.assertEqual(exits[0]["observed"]["durable"]["local"]["mask"], 0)
                self.assertIsNone(exits[0]["observed"]["durable"]["fence"])
                self.assertEqual(exits[0]["observed"]["spend"]["revision"], 1)
                startup = rows(trace, "startup")[-1]
                self.assertEqual(startup["observed"]["durable"]["local"]["mask"], 32)
                self.assertEqual(returned(trace, "finish")[-1]["observed"]["response"],
                                 {"code": "BLOCK_EFFECT_UNCERTAIN", "new_effect": False})
                self.assertEqual(exits[0]["observed"]["spend"], exits[-1]["observed"]["spend"])
                expected_working_mask = 1 if case.endswith("DENIAL") else 0
                self.assertEqual(last["observed"]["working"]["local"]["mask"], expected_working_mask)
                self.observe_case(case, ["actual process exit after second sampled fence and before consumer COMMIT",
                                         "uncommitted state disappears; independent reservation remains",
                                         "real service reopening records STARTUP and same ID cannot be repeated"])

    def test_05_process_cuts_after_integrated_commit(self):
        for case in ("CUT_AFTER_PASS_COMMIT", "CUT_AFTER_DENIAL_COMMIT"):
            with self.subTest(case=case):
                trace = self.traces[case]
                commit = rows(trace, "tx_commit", "finish")[0]
                self.assertIn("os._exit(73)", commit["raw"]["next_instruction"])
                self.assertIsNone(commit["observed"]["response"])
                exits = rows(trace, "process_exit")
                self.assertEqual(exits[0]["raw"]["actual_exit_code"], 73)
                self.assertIsNone(exits[0]["observed"]["response"])
                self.assertEqual(exits[0]["observed"]["durable"], commit["observed"]["durable"])
                self.assertEqual(len(rows(trace, "reserve")), 1)
                startup = rows(trace, "startup")[-1]
                previous = exits[0]["observed"]["durable"]["local"]
                self.assertEqual(startup["observed"]["durable"]["local"]["mask"], previous["mask"] | 32)
                self.assertEqual(startup["observed"]["durable"]["local"]["level"], previous["level"])
                reply = returned(trace, "finish")[-1]
                if case == "CUT_AFTER_PASS_COMMIT":
                    self.assertEqual(previous["level"], 1)
                    self.assertEqual(exits[0]["observed"]["durable"]["inbox"]["status"], "DONE")
                    self.assertEqual(reply["observed"]["response"], {"code": "ACK_EFFECT_HISTORY", "new_effect": False})
                    self.assertEqual(exits[0]["observed"]["durable"]["inbox"]["effect"],
                                     exits[-1]["observed"]["durable"]["inbox"]["effect"])
                else:
                    self.assertEqual(previous["level"], 0)
                    self.assertEqual(previous["mask"], 1)
                    self.assertFalse(exits[0]["observed"]["durable"]["inbox"]["delivery"]["eligible"])
                    self.assertIsNone(exits[0]["observed"]["durable"]["inbox"]["effect"])
                    self.assertEqual(reply["observed"]["response"], {"code": "BLOCK_COMMIT_FENCE_HISTORY", "new_effect": False})
                self.assertEqual(exits[0]["observed"]["spend"], exits[-1]["observed"]["spend"])
                self.observe_case(case, ["actual process exit after integrated consumer COMMIT but before handle return",
                                         "independent readback distinguishes durable publication from missing reply",
                                         "normal reopening preserves stored level and adds STARTUP; replay makes no new effect"])


def main():
    global CAPTURE_DIR
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--captures", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    CAPTURE_DIR = args.captures.resolve()
    if args.report.exists():
        raise FileExistsError("refusing to overwrite a test execution receipt")
    started = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(IntegratedCaptureTests)
    actual_methods = [test._testMethodName for test in suite]
    if actual_methods != list(EXPECTED_TEST_METHODS):
        raise AssertionError("test method inventory changed")
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    print(stream.getvalue(), end="")
    import cryptography
    source_sha = {str(path.relative_to(HERE.parents[1])): sha256(path)
                  for path in (HERE / "integrated_service.py", HERE / "trace_capture.py", Path(__file__))}
    report = {"schema": "FCI-COU40-REF4-TESTS/1", "status": "PASS_EXECUTED_SCOPED" if result.wasSuccessful() else "FAIL_EXECUTED",
              "started_utc": started, "completed_utc": datetime.now(timezone.utc).isoformat(),
              "elapsed_seconds": round(time.monotonic()-start, 6), "executed_test_methods": result.testsRun,
              "test_method_names": actual_methods, "observed_subcases": len(OBSERVATIONS),
              "observations": OBSERVATIONS, "failures": [str(item) for item in result.failures],
              "errors": [str(item) for item in result.errors], "skipped": result.skipped,
              "source_sha256": source_sha, "capture_sha256": sha256(CAPTURE_DIR / "CAPTURES.json"),
              "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                              "cryptography": cryptography.__version__, "python_executable": str(Path(sys.executable).resolve())},
              "runtime_campaigns_reexecuted_by_tests": 0,
              "scope": "Five checks of seven new integrated-entry captured scenarios; separate Lean prefix comparison required"}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
