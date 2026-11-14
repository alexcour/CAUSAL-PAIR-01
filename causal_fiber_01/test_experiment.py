import unittest
from unittest.mock import patch

import experiment


class FiberAuditTests(unittest.TestCase):
    def test_complete_binary_enrichment_search(self):
        result = experiment.run()
        self.assertEqual(result["binary_enrichments_checked"], 16)
        self.assertEqual(result["sufficient_binary_enrichments"], 4)

    def test_ignoring_causal_order_is_detected(self):
        with patch.object(experiment, "extra", lambda h: h.fresh):
            with self.assertRaisesRegex(RuntimeError, "enriched reconstruction"):
                experiment.run()

    def test_ignoring_freshness_is_detected(self):
        with patch.object(experiment, "extra", lambda h: h.before):
            with self.assertRaisesRegex(RuntimeError, "enriched reconstruction"):
                experiment.run()

    def test_constant_extra_is_detected(self):
        with patch.object(experiment, "extra", lambda h: True):
            with self.assertRaisesRegex(RuntimeError, "enriched reconstruction"):
                experiment.run()

    def test_adding_hidden_verdict_to_observation_is_detected(self):
        with patch.object(experiment, "observe", lambda h: {"verdict": experiment.verdict(h)}):
            with self.assertRaisesRegex(RuntimeError, "collision pairs"):
                experiment.run()


if __name__ == "__main__":
    unittest.main()
