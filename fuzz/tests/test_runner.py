#!/usr/bin/env python3

import contextlib
import importlib.util
import io
import pathlib
import tempfile
import unittest
from unittest import mock


RUNNER_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "runner.py"
SPEC = importlib.util.spec_from_file_location("fuzz_runner", RUNNER_PATH)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class CoverageProfileMergeTests(unittest.TestCase):
    def test_single_raw_profile_is_indexed_instead_of_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_profile = pathlib.Path(directory) / "one.profraw"
            merged_profile = pathlib.Path(directory) / "merged.profdata"
            raw_profile.write_bytes(b"raw profile")

            with mock.patch.object(runner.subprocess, "run") as run:
                runner.merge_coverage_profiles(None, [raw_profile], merged_profile)

            run.assert_called_once_with(
                [runner.LLVM_PROFDATA, "merge", "-sparse", str(raw_profile), "-o", str(merged_profile)],
                check=True,
            )

    def test_compact_summary_keeps_report_metrics_without_per_line_ids(self):
        compact = runner.compact_coverage_summary({
            "label": "final",
            "inputs": 4,
            "duration_seconds": 1.5,
            "nginx_source": {"lines": {"covered": 2, "total": 4, "percent": 50.0}},
            "whole_instrumented_build": {"lines": {"count": 10, "covered": 2}},
            "scopes": [{
                "id": "TEST-SCOPE",
                "file": "src/http/ngx_http_parse.c",
                "functions": ["ngx_http_parse_request_line"],
                "lines": {"covered": 2, "total": 4, "percent": 50.0,
                          "covered_line_ids": ["file.c:1", "file.c:2"]},
                "branches": {"covered": 3, "total": 8, "percent": 37.5,
                             "covered_branch_ids": ["file.c:1:0"]},
            }],
        })

        self.assertEqual(compact["scopes"][0]["lines"], {
            "covered": 2, "total": 4, "percent": 50.0,
        })
        self.assertNotIn("covered_line_ids", compact["scopes"][0]["lines"])
        self.assertEqual(compact["inputs"], 4)


class RunStorageTests(unittest.TestCase):
    def test_corpora_remain_uncompressed_and_are_summarized(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = pathlib.Path(directory) / "run"
            input_dir = run_dir / "corpus_in"
            output_dir = run_dir / "corpus_out"
            input_dir.mkdir(parents=True)
            output_dir.mkdir()
            (input_dir / "seed").write_bytes(b"seed input")
            (output_dir / "generated").write_bytes(b"generated input")

            summary = runner.summarize_run_corpora(run_dir)

            self.assertTrue(input_dir.is_dir())
            self.assertTrue(output_dir.is_dir())
            self.assertEqual(summary["corpus_in"]["files"], 1)
            self.assertEqual(summary["corpus_out"]["files"], 1)
            self.assertFalse((run_dir / "corpus.tar.gz").exists())

    def test_completed_round_log_is_compressed_without_content_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = pathlib.Path(directory) / "fuzzer-round-0001.log"
            log_path.write_text("fuzzer output\n" * 100)

            runner.compact_run_log(log_path)

            self.assertFalse(log_path.exists())
            compressed = pathlib.Path(str(log_path) + ".gz")
            self.assertTrue(compressed.is_file())
            with runner.gzip.open(compressed, "rt") as stream:
                self.assertEqual(stream.read(), "fuzzer output\n" * 100)

    def test_campaign_timeline_stays_plain_while_round_logs_are_compressed(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = pathlib.Path(directory)
            campaign_log = logs / "campaign.log"
            round_log = logs / "fuzzer-round-0001.log"
            campaign_log.write_text("timestamped campaign timeline\n")
            round_log.write_text("fuzzer output\n")

            runner.compact_campaign_round_logs(logs)

            self.assertTrue(campaign_log.is_file())
            self.assertEqual(campaign_log.read_text(), "timestamped campaign timeline\n")
            self.assertFalse(round_log.exists())
            self.assertTrue(pathlib.Path(str(round_log) + ".gz").is_file())


class FindingStopReasonTests(unittest.TestCase):
    def reason(self, *symptoms):
        return runner.finding_stop_reason([{"symptom": symptom} for symptom in symptoms])

    def test_crash(self):
        self.assertEqual(self.reason("crash"), "crash")

    def test_timeout(self):
        self.assertEqual(self.reason("timeout"), "timeout")

    def test_oom(self):
        self.assertEqual(self.reason("oom"), "oom")

    def test_slow(self):
        self.assertEqual(self.reason("slow"), "slow")

    def test_highest_severity_wins_for_mixed_findings(self):
        self.assertEqual(self.reason("slow", "crash", "oom", "timeout"), "timeout")
        self.assertEqual(self.reason("slow", "crash", "oom"), "oom")

    def test_campaign_is_configured_to_keep_running_after_crashes(self):
        self.assertEqual(
            runner.campaign_resilience_flags(),
            ["-fork=1", "-ignore_crashes=1"],
        )

    def test_fork_mode_accepts_a_recorded_worker_crash_exit(self):
        finding = [{"symptom": "crash", "status": "needs_analysis"}]
        self.assertTrue(runner.expected_fork_exit(77, finding))
        self.assertFalse(runner.expected_fork_exit(77, []))
        self.assertFalse(runner.expected_fork_exit(1, finding))

    def test_fork_mode_accepts_last_worker_exit_after_supervisor_time_limit(self):
        log = "INFO: fuzzed for 305 seconds, wrapping up soon\nINFO: exiting: 1 time: 305s\n"
        self.assertTrue(runner.expected_fork_exit(1, [], log))
        self.assertFalse(runner.expected_fork_exit(1, [], "INFO: exiting: 1 time: 305s\n"))
        self.assertFalse(runner.expected_fork_exit(1, [], log.replace("exiting: 1", "exiting: 0")))

    def test_fork_worker_counters_capture_latest_stats(self):
        log = "oom/timeout/crash: 0/0/3\ntime: 305s\noom/timeout/crash: 1/2/14\n"
        self.assertEqual(
            runner.fork_worker_counters(log),
            {"oom": 1, "timeouts": 2, "crashes": 14},
        )


class CampaignLogFormattingTests(unittest.TestCase):
    def test_elapsed_duration_uses_unbounded_hours(self):
        self.assertEqual(runner.elapsed_hms(59), "00:00:59")
        self.assertEqual(runner.elapsed_hms(7200), "02:00:00")
        self.assertEqual(runner.elapsed_hms(90061), "25:01:01")

    def test_campaign_events_show_total_and_no_growth_duration(self):
        context = {
            "started": 0,
            "last_growth": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            log_path = pathlib.Path(directory) / "campaign.log"
            output = io.StringIO()
            with mock.patch.object(runner.time, "monotonic", return_value=7200):
                with contextlib.redirect_stdout(output):
                    runner.campaign_log_event(log_path, context, "watchdog event=heartbeat")

            self.assertIn("elapsed=02:00:00", output.getvalue())
            self.assertIn("no_coverage_growth=02:00:00", output.getvalue())
            self.assertIn("watchdog event=heartbeat", log_path.read_text())


class ReplaySummaryTests(unittest.TestCase):
    def test_successful_replay_is_not_reproduction(self):
        self.assertEqual(
            runner.replay_summary({"exit_code": 0}),
            "not reproduced (exit 0)",
        )

    def test_nonzero_exit_requires_log_inspection(self):
        self.assertEqual(
            runner.replay_summary({"exit_code": 77}),
            "exit 77; inspect log",
        )

    def test_missing_replay_is_reported(self):
        self.assertEqual(runner.replay_summary(None), "not run")


class RegressionCheckTests(unittest.TestCase):
    def test_input_discovery_skips_docs_and_encoded_hex_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "README.md").write_text("docs")
            (root / "input.hex").write_text("00")
            (root / "._input.hex").write_text("fork data")
            (root / ".DS_Store").write_bytes(b"metadata")
            (root / "input").write_bytes(b"\x00")
            (root / "decoded-input").write_bytes(b"\x00")
            (root / "input.textproto").write_text("request {}")

            self.assertEqual(
                [path.name for path in runner.regression_input_files(root)],
                ["decoded-input", "input", "input.textproto"],
            )

    def test_input_discovery_rejects_missing_decoded_hex_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "missing.hex").write_text("00")
            with self.assertRaises(FileNotFoundError):
                runner.regression_input_files(root)

    def test_requires_a_nonzero_exit_and_sanitizer_diagnostic(self):
        self.assertTrue(runner.regression_failure_detected(
            77, "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior"
        ))
        self.assertTrue(runner.regression_failure_detected(
            1, "ERROR: AddressSanitizer: heap-buffer-overflow"
        ))
        self.assertFalse(runner.regression_failure_detected(
            0, "SUMMARY: UndefinedBehaviorSanitizer: stale log"
        ))
        self.assertFalse(runner.regression_failure_detected(77, "libFuzzer: deadly signal"))


class FindingReportTests(unittest.TestCase):
    def test_report_separates_observed_symptom_from_replay_result(self):
        manifest = {
            "run_id": "test-run",
            "kind": "smoke",
            "status": "finding",
            "stop_reason": "timeout",
            "exit_code": 70,
            "duration_seconds": 12,
            "findings": [{
                "input": "artifacts/timeout-example",
                "symptom": "timeout",
                "status": "needs_analysis",
                "sanitizer_replay": {"exit_code": 0},
                "without_sanitizers_replay": {"exit_code": 0},
            }],
            "regression_check": {
                "target": "NGX-IF14",
                "passed": True,
                "cases": [{"expected_sanitizer_diagnostic": True}],
            },
            "coverage": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            runner.write_report(pathlib.Path(directory), manifest)
            report = (pathlib.Path(directory) / "report.md").read_text()

        self.assertIn("Observed symptom", report)
        self.assertIn("`timeout`", report)
        self.assertIn("not reproduced (exit 0)", report)
        self.assertIn("`needs_analysis`", report)
        self.assertIn("Findings requiring analysis: `1`", report)
        self.assertIn("Regression preflight: `1/1 reproduced`", report)

    def test_confirmed_findings_are_not_counted_as_pending(self):
        self.assertEqual(
            runner.count_findings_requiring_analysis([
                {"status": "confirmed"},
                {"status": "needs_analysis"},
            ]),
            1,
        )


if __name__ == "__main__":
    unittest.main()
