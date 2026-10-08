#!/usr/bin/env python3

import importlib.util
import pathlib
import unittest


SCRIPT_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "campaign-parallel.py"
SPEC = importlib.util.spec_from_file_location("campaign_parallel", SCRIPT_PATH)
campaign_parallel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign_parallel)


class CampaignParallelSummaryTests(unittest.TestCase):
    def test_finding_is_reported_as_finding_but_successfully_completed(self):
        result = {
            "process_exit_code": 0,
            "status": "finding",
            "stop_reason": "crash",
        }
        self.assertEqual(
            campaign_parallel.target_result_label(result),
            "finding (stop_reason=crash)",
        )
        self.assertTrue(campaign_parallel.target_result_completed(result))

    def test_finding_exit_77_is_expected_runner_result(self):
        result = {
            "process_exit_code": 77,
            "status": "finding",
            "stop_reason": "crash",
        }
        self.assertEqual(
            campaign_parallel.target_result_label(result),
            "finding (stop_reason=crash)",
        )
        self.assertTrue(campaign_parallel.target_result_completed(result))

    def test_passed_campaign_is_reported_as_passed(self):
        result = {"process_exit_code": 0, "status": "passed"}
        self.assertEqual(campaign_parallel.target_result_label(result), "passed")
        self.assertTrue(campaign_parallel.target_result_completed(result))

    def test_failed_or_unavailable_manifest_is_not_success(self):
        failed = {"process_exit_code": 0, "status": "failed", "stop_reason": "infrastructure_error"}
        self.assertIn("failed", campaign_parallel.target_result_label(failed))
        self.assertFalse(campaign_parallel.target_result_completed(failed))

        missing = {"process_exit_code": 0, "status": "missing_manifest"}
        self.assertFalse(campaign_parallel.target_result_completed(missing))

    def test_nonzero_wrapper_exit_is_orchestration_error(self):
        result = {"process_exit_code": 2, "status": "finding", "stop_reason": "crash"}
        self.assertEqual(
            campaign_parallel.target_result_label(result),
            "orchestration_error (exit 2)",
        )
        self.assertFalse(campaign_parallel.target_result_completed(result))


if __name__ == "__main__":
    unittest.main()
