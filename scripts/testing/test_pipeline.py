import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pipeline import (EXPECTED_STREAMS, PipelineObserver, account, database_sql,
                      distribution, lag_complete, lag_maxima, parse_database,
                      parse_receipts, request_path, zero_lag)
from run_experiment import arguments, main


def db_row(**values):
    row = dict(log_id=1, request_id="Abc", status_code=200,
               log_row_at="2026-11-01T03:00:00.500000Z",
               waf_access_at="2026-11-01T03:00:00+00:00",
               ai_detection_count=0, waf_detection_count=0)
    return {**row, **values}


def snapshot(lag=0, **values):
    return dict(code=0, at="2026-11-01T03:00:02Z", label="fake",
                rows=[dict(group=g, topic=t, partition=0, lag=lag)
                      for g, t in sorted(EXPECTED_STREAMS)], **values)


class Clock:
    value = 0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class PipelineTests(unittest.TestCase):
    def test_sql_is_read_only_and_escapes_run_path_as_hex(self):
        run_id = "20261101T120000+0900-local-normal-smoke-r08"
        sql = database_sql(run_id)
        self.assertIn("START TRANSACTION READ ONLY;", sql)
        self.assertTrue(sql.endswith("ROLLBACK;\n"))
        self.assertIn("BINARY n.request_url = BINARY CONVERT(0x", sql)
        self.assertIn(request_path(run_id).encode().hex(), sql)
        self.assertNotIn(run_id, sql)
        self.assertIn("%2B0900", request_path(run_id))
        self.assertNotIn("DELETE", sql)

    def test_db_time_basis_is_explicit_and_raw_datetime_is_retained(self):
        sql = database_sql("run", "+09:00")
        self.assertIn("CONVERT_TZ(n.created_at, '+09:00', '+00:00')", sql)
        self.assertIn("'log_row_raw'", sql)
        with self.assertRaises(ValueError):
            database_sql("run", "unverified")

    def test_future_db_timestamp_is_not_reported_as_nine_hour_latency(self):
        result = account([db_row(log_row_at="2026-11-01T12:00:00Z")],
                         [dict(log_id=1, handled_at="2026-11-01T03:00:01Z")], 1)
        self.assertIsNone(result["latency_ms"]["waf_access_to_log_row"]["avg_ms"])
        self.assertIsNone(result["latency_ms"]["log_row_to_ai_handled"]["avg_ms"])
        self.assertEqual(result["latency_ms"]["waf_access_to_ai_handled"]["avg_ms"], 1000)

    def test_database_validation_rejects_bad_or_duplicate_rows(self):
        for value in ("broken", "[]", json.dumps(db_row(log_id=True)),
                      json.dumps(db_row(ai_detection_count=-1)),
                      json.dumps(db_row()) + "\n" + json.dumps(db_row())):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_database(value)
        self.assertEqual(parse_database(""), [])
        rows = parse_database(json.dumps(db_row(ip_address="do-not-store")))
        self.assertNotIn("ip_address", rows[0])

    def test_receipts_are_scoped_and_use_offset_timestamps(self):
        source = "\n".join([
            "backend | 2026-11-01T03:00:02.123456789Z 2026-11-01T12:00:01+09:00 INFO AI analysis result received. logId=1",
            "backend | AI analysis result received. logId=1",
            "2026-11-01T03:00:01Z AI analysis result received. logId=999",
            "2026-11-01T03:00:01Z unrelated secret=do-not-store",
        ])
        found = parse_receipts(source, {1})
        self.assertEqual(found, [dict(log_id=1, handled_at="2026-11-01T12:00:01+09:00")])
        self.assertNotIn("secret", json.dumps(found))

    def test_normal_result_without_threat_row_is_handled(self):
        counts = account([db_row()], [dict(log_id=1, handled_at="2026-11-01T03:00:01Z")], 1)["counts"]
        self.assertEqual(counts["ai_handled_logs"], 1)
        self.assertEqual(counts["ai_handled_without_detection"], 1)
        self.assertEqual(counts["ai_unconfirmed_logs"], 0)
        self.assertIsNone(counts["processing_failures"])
        self.assertIsNone(counts["policy_excluded"])
        self.assertIsNone(counts["dlt_records"])

    def test_threat_row_alone_does_not_prove_result_handler_completion(self):
        result = account([db_row(ai_detection_count=1)], [], 1)
        self.assertEqual(result["counts"]["ai_handled_logs"], 0)
        self.assertEqual(result["counts"]["ai_unconfirmed_logs"], 1)
        self.assertEqual(result["latency_ms"]["log_row_to_ai_handled"]["count"], 0)

    def test_receipt_duplicates_are_separate_from_db_duplicates(self):
        receipts = [dict(log_id=1, handled_at="2026-11-01T03:00:02Z"),
                    dict(log_id=1, handled_at="2026-11-01T03:00:01Z")]
        result = account([db_row()], receipts, 1)
        self.assertEqual(result["counts"]["extra_ai_receipt_events"], 1)
        self.assertEqual(result["counts"]["logs_with_duplicate_ai_detections"], 0)
        self.assertEqual(result["latency_ms"]["log_row_to_ai_handled"]["avg_ms"], 500)

    def test_request_id_case_and_missing_are_preserved(self):
        rows = [db_row(), db_row(log_id=2, request_id="abc"),
                db_row(log_id=3, request_id="abc"), db_row(log_id=4, request_id=None)]
        counts = account(rows, [], 4)["counts"]
        self.assertEqual(counts["distinct_request_ids"], 2)
        self.assertEqual(counts["duplicate_request_ids"], 1)
        self.assertEqual(counts["missing_request_ids"], 1)

    def test_negative_or_missing_latency_is_not_zero(self):
        result = account([db_row(log_row_at="2026-11-01T02:59:59Z")], [], 1)
        stats = result["latency_ms"]["waf_access_to_log_row"]
        self.assertEqual(stats["count"], 0)
        self.assertIsNone(stats["avg_ms"])
        self.assertEqual(result["invalid_or_unobserved_latency"]["waf_access_to_log_row"], 1)
        self.assertIsNone(distribution([])["p99_ms"])
        self.assertEqual(distribution([0])["p99_ms"], 0)

    def test_latency_median_handles_empty_single_odd_and_even_samples(self):
        self.assertIsNone(distribution([])["p50_ms"])
        self.assertEqual(distribution([0])["p50_ms"], 0)
        self.assertEqual(distribution([9])["p50_ms"], 9)
        self.assertEqual(distribution([1, 100, 4])["p50_ms"], 4)
        self.assertEqual(distribution([1, 100, 4, 2])["p50_ms"], 3)

    def test_missing_stream_partition_or_unknown_lag_does_not_mean_zero(self):
        good = snapshot()
        keys = {(r["group"], r["topic"], r["partition"]) for r in good["rows"]}
        self.assertTrue(zero_lag(good, keys))
        missing = snapshot()
        missing["rows"].pop()
        self.assertFalse(lag_complete(missing, keys))
        self.assertFalse(zero_lag(snapshot(lag=None), keys))
        self.assertFalse(lag_complete(good, keys | {("log-group", "log-topic", 1)}))
        self.assertFalse(zero_lag(snapshot(lag=-1), keys))

    def test_lag_peaks_preserve_unknown_as_unknown(self):
        data = lag_maxima([snapshot(lag=None), snapshot(lag=7), snapshot(lag=0)])
        self.assertEqual(len(data), 4)
        self.assertTrue(all(r["observed_max_lag"] == 7 for r in data))
        self.assertTrue(all(r["unknown_samples"] == 1 for r in data))
        self.assertTrue(all(r["observed_max_lag"] is None for r in lag_maxima([snapshot(lag=None)])))

    def observe(self, directory, *, rows=None, logs=None, lag_value=0, db_error=False):
        output = Path(directory)
        (output / "raw").mkdir()
        rows = [db_row()] if rows is None else rows
        logs = "2026-11-01T03:00:01Z AI analysis result received. logId=1" if logs is None else logs
        calls, events = [], []

        def command(args, **kwargs):
            calls.append((args, kwargs))
            return dict(code=int(db_error) if "db" in args else 0,
                        stdout="\n".join(json.dumps(r) for r in rows) if "db" in args else logs,
                        stderr="do-not-store")

        def lag(label):
            item = snapshot(lag=lag_value)
            item["label"] = label
            return item

        observer = PipelineObserver(output, ["docker", "compose"], "fake+id", command,
                                    lag, lambda *e: events.append(e), interval=5, drain_seconds=10)
        return observer, calls, events

    def test_observer_finishes_only_after_two_zero_lag_and_completion_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            observer, calls, _ = self.observe(directory)
            observer.preflight(snapshot())
            observer.snapshot("during-0001")
            clock = Clock()
            with patch("pipeline.time.monotonic", clock.monotonic), patch("pipeline.time.sleep", clock.sleep):
                result = observer.finish(1, "2026-11-01T03:00:00Z", "2026-11-01T03:00:01Z")
            self.assertEqual(result["verdict"], "PASS")
            self.assertEqual(result["post_load_rounds"], 2)
            self.assertEqual(result["counts"]["ai_handled_without_detection"], 1)
            self.assertTrue(all("input_text" in kwargs for args, kwargs in calls if "db" in args))
            text = "".join(p.read_text(encoding="utf-8") for p in (Path(directory)/"raw").glob("*.json"))
            self.assertNotIn("do-not-store", text)
            self.assertIn("MYSQL_ROOT_PASSWORD", calls[0][0][-1])

    def test_missing_receipt_times_out_as_unconfirmed_even_with_zero_lag(self):
        with tempfile.TemporaryDirectory() as directory:
            observer, _, _ = self.observe(directory, logs="")
            observer.preflight(snapshot())
            clock = Clock()
            with patch("pipeline.time.monotonic", clock.monotonic), patch("pipeline.time.sleep", clock.sleep):
                result = observer.finish(1, "2026-11-01T03:00:00Z", "2026-11-01T03:00:01Z")
            self.assertEqual(result["verdict"], "INCONCLUSIVE")
            self.assertEqual(result["counts"]["ai_unconfirmed_logs"], 1)
            self.assertIsNone(result["post_load_zero_lag_confirmed_at"])

    def test_missing_db_rows_fail_only_the_bounded_arrival_criterion(self):
        with tempfile.TemporaryDirectory() as directory:
            observer, _, _ = self.observe(directory, rows=[])
            observer.preflight(snapshot())
            clock = Clock()
            with patch("pipeline.time.monotonic", clock.monotonic), patch("pipeline.time.sleep", clock.sleep):
                result = observer.finish(1, "2026-11-01T03:00:00Z", "2026-11-01T03:00:01Z")
            self.assertEqual(result["verdict"], "FAIL")
            self.assertTrue(any("영구 누락" in r for r in result["reasons"]))

    def test_cancelled_final_observation_does_not_fabricate_zero_database_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            observer,calls,_=self.observe(directory)
            observer.preflight(snapshot())
            observer.cancelled=lambda:True
            before=len(calls)
            result=observer.finish(1,"2026-11-01T03:00:00Z","2026-11-01T03:00:01Z")
            self.assertEqual(result["verdict"],"INCONCLUSIVE")
            self.assertIsNone(result["counts"]["saved_logs"])
            self.assertTrue(result["final_observation_cancelled"])
            self.assertEqual(len(calls),before)

    def test_preflight_blocks_on_missing_stream_or_db_read_failure(self):
        for db_error, before in ((False, dict(code=0, rows=[])), (True, snapshot())):
            with self.subTest(db_error=db_error), tempfile.TemporaryDirectory() as directory:
                observer, _, _ = self.observe(directory, db_error=db_error)
                with self.assertRaises(RuntimeError):
                    observer.preflight(before)

    def test_instrumentation_dry_run_does_not_call_services_or_create_files(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), \
             patch("run_experiment.ROOT", Path(directory)), \
             patch("run_experiment.command", side_effect=AssertionError("external command")), \
             patch("run_experiment.reserve", side_effect=AssertionError("write")):
            self.assertEqual(main(["--dry-run", "--observe-pipeline", "--db-time-offset", "+00:00"]), 0)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_instrumentation_limits_are_validated_before_execution(self):
        for args in (["--lag-interval", "0"], ["--drain-seconds", "121"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                arguments(["--dry-run", "--observe-pipeline", *args])

    def test_pipeline_requires_database_time_basis_before_any_service_call(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            arguments(["--dry-run", "--observe-pipeline"])


if __name__ == "__main__":
    unittest.main()
