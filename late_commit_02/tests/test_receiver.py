import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("late_commit", Path(__file__).parents[1] / "experiment.py")
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


class ReceiverContractTests(unittest.TestCase):
    def run_case(self, architecture, schedule, fault="none"):
        with tempfile.TemporaryDirectory() as directory:
            return model.run_case(Path(directory), architecture, schedule, fault)

    def test_pending_http_is_not_a_committed_effect(self):
        row = self.run_case("check_before_call", "recovery_first")
        self.assertEqual(row["controller_observation"]["lookup"]["body"], {"state": "NOT_FOUND"})
        self.assertEqual(row["effects"], [(1, model.K, "recovery"), (2, model.K, "old")])
        self.assertEqual(row["events"][0]["attempt"], "old")

    def test_fencing_does_not_reconcile_a_past_commit(self):
        self.assertEqual(self.run_case("receiver_fence_only", "old_first")["final_effects"], 2)
        row = self.run_case("receiver_fence_only", "recovery_first")
        self.assertEqual(row["final_effects"], 1)
        self.assertEqual(row["old_response"]["http_status"], 409)

    def test_atomic_idempotency_preserves_the_first_result(self):
        for schedule in ("old_first", "recovery_first"):
            with self.subTest(schedule=schedule):
                row = self.run_case("atomic_idempotency", schedule)
                self.assertEqual(row["final_effects"], 1)
                self.assertEqual(row["old_response"]["body"]["result"], row["recovery_response"]["body"]["result"])

    def test_old_request_between_fence_and_execution_is_rejected(self):
        row = self.run_case("receiver_fence_only", "old_after_fence")
        self.assertEqual(row["effects"], [(1, model.K, "recovery")])
        self.assertEqual(row["old_response"], {"http_status": 409, "body": {"state": "STALE"}})

    def test_all_architectures_complete_without_an_old_request(self):
        for architecture in model.ARCHITECTURES:
            with self.subTest(architecture=architecture):
                row = self.run_case(architecture, "no_old_request")
                self.assertEqual(row["effects"], [(1, model.K, "recovery")])

    def test_breaking_each_protection_exposes_a_duplicate(self):
        for architecture, schedule, fault in (
                ("receiver_fence_only", "recovery_first", "disable_fence"),
                ("atomic_idempotency", "old_first", "disable_dedup"),
                ("fence_and_reconcile", "old_first", "ignore_prior_commit")):
            with self.subTest(fault=fault):
                row = self.run_case(architecture, schedule, fault)
                self.assertFalse(row["outcome_matches"])
                self.assertEqual(row["final_effects"], 2)


if __name__ == "__main__":
    unittest.main()
