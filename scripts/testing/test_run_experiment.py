import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import io
import threading

from metrics import EVALUATION_VERSION, normalize, assess, judge, parse_lag, resource_peaks
from run_experiment import arguments, main, reserve, format_record_time, report_text


class ExperimentTests(unittest.TestCase):
    def test_report_time_uses_slashes_and_kst(self):
        self.assertEqual(format_record_time("2026-10-31T06:48:08Z"),
                         "2026/10/31 15:48:08 +09:00")
        self.assertEqual(format_record_time("2026-10-31T15:48:08+09:00"),
                         "2026/10/31 15:48:08 +09:00")

    def test_missing_or_naive_time_is_not_assumed(self):
        self.assertEqual(format_record_time(None, "미실행"), "미실행")
        self.assertEqual(format_record_time("2026-10-31T15:48:08"),
                         "시간대 확인 필요")

    def test_report_converts_display_without_changing_evidence(self):
        manifest = dict(id="test", planned_at="2026-10-31T06:48:07Z",
                        ended_at="2026-10-31T06:48:08Z", state="BLOCKED",
                        url="http://127.0.0.1/", rate=1, seconds=60,
                        interval=5, target_count=60)
        measured = dict(http={}, verdict="INCONCLUSIVE", docker_samples=0,
                        resource_peaks={}, kafka_successful_snapshots=0)
        events = [dict(at="2026-10-31T06:48:08Z", kind="error", message="test")]
        text = report_text(manifest, measured, events, Path("evidence"))
        self.assertTrue(text.startswith("# 실험 기록: 2026/10/31 — "))
        self.assertIn("실험 ID: test", text)
        self.assertIn("실험일자: 2026/10/31", text)
        self.assertIn("미실행 / 2026/10/31 15:48:08 +09:00", text)
        self.assertIn('"at": "2026/10/31 15:48:08 +09:00"', text)
        self.assertEqual(events[0]["at"], "2026-10-31T06:48:08Z")

    def setUp(self):
        self.capture = contextlib.ExitStack()
        self.capture.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.capture.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.addCleanup(self.capture.close)

    def run_fake(self, root, interrupted=False, broken_json=False, *,
                 actual_count=60, seconds=60, ok_rate=1, dropped=0, exit_code=0,
                 p99=40, include_p99=True, p50=8, include_p50=True,
                 observe_pipeline=False, db_denied=False,
                 profile=False, point_status=200, low_memory=False):
        sampled = threading.Event()
        launched = threading.Event()
        finished = threading.Event()
        observe_pipeline = observe_pipeline or profile
        if profile:
            seconds = 120
        duration = {"avg": 10, "p(95)": 25, "max": 60}
        if include_p50:
            duration["med"] = p50
        if include_p99:
            duration["p(99)"] = p99
        summary = {"results": {"metrics": [
            {"name": "http_reqs", "values": {"count": actual_count}},
            {"name": "iterations", "values": {"count": actual_count}},
            {"name": "http_req_duration", "values": duration},
            {"name": "normal_ok", "values": {"rate": ok_rate}},
            {"name": "dropped_iterations", "values": {"count": dropped}},
        ]}}

        def fake_command(args, **kwargs):
            text = ""
            if "stats" in args:
                sampled.set()
                text = '{"Name":"fake-ai","CPUPerc":"180%","MemPerc":"20%"}'
            elif "kafka-consumer-groups" in args:
                text = ("GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID\n"
                        "fake-group log-topic 0 10 10 0 c h x\n")
                if observe_pipeline:
                    from pipeline import EXPECTED_STREAMS
                    text = "GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID\n"
                    text += "\n".join(f"{g} {t} 0 10 10 0 c h x" for g, t in EXPECTED_STREAMS)
            elif "db" in args:
                if db_denied:
                    return dict(code=1, stdout="", stderr="access denied")
                if launched.is_set():
                    text = "\n".join(json.dumps(dict(
                        log_id=i, request_id=f"request-{i}", status_code=200,
                        log_row_at="2026-11-01T03:00:00.500000Z",
                        waf_access_at="2026-11-01T03:00:00+00:00",
                        ai_detection_count=0, waf_detection_count=0
                    )) for i in range(1, actual_count + 1))
            elif "logs" in args:
                text = "\n".join(f"2026-11-01T03:00:01Z INFO AI analysis result received. logId={i}"
                                 for i in range(1, actual_count + 1))
            elif "-q" in args:
                text = "fake-container"
            elif "inspect" in args:
                text = "fake-container fake-image fake-digest"
                if any("restart_count" in arg for arg in args):
                    from load_policy import load_policy
                    policy,_=load_policy()
                    text="\n".join(json.dumps(dict(id="id-"+name,service=name,running=True,
                        oom_killed=False,restart_count=0,started_at="2026-11-01T00:00:00Z"))
                        for name in policy["required_services"])
            elif "rev-parse" in args:
                text = "fake-sha"
            return {"code": 0, "stdout": text, "stderr": ""}

        class FakeProcess:
            done = False
            interrupted_once = False

            def __init__(self, args, **kwargs):
                launched.set()
                path = Path(kwargs["env"]["SUMMARY_PATH"])
                path.write_text("broken" if broken_json else json.dumps(summary), encoding="utf-8")
                if profile:
                    from datetime import datetime,timedelta,timezone
                    with (path.parent/"k6-points.jsonl").open("w",encoding="utf-8") as stream:
                        for i in range(actual_count):
                            at=(datetime(2026,11,1,tzinfo=timezone.utc)+timedelta(seconds=i)).isoformat()
                            stream.write(json.dumps(dict(type="Point",metric="http_req_duration",
                                data=dict(time=at,value=5,tags=dict(status=str(point_status if i==0 else 200)))))+"\n")

            def wait(self, **kwargs):
                sampled.wait(timeout=2)
                if interrupted and not self.interrupted_once:
                    self.interrupted_once = True
                    raise KeyboardInterrupt()
                self.done = True
                return exit_code

            def poll(self):
                if profile and point_status==200 and sampled.is_set():
                    self.done=True
                    finished.set()
                return 0 if self.done else None

            def terminate(self):
                self.done = True
                finished.set()

            def kill(self):
                self.done = True

        (root / ".env").write_text("", encoding="utf-8")
        with patch("run_experiment.ROOT", root), \
             patch("run_experiment.tool_versions", return_value={"k6": "fake"}), \
             patch("run_experiment.command", side_effect=fake_command), \
             patch("run_experiment.subprocess.Popen", FakeProcess), \
             patch("guard.host_memory", return_value=dict(total_bytes=8*1024**3,
                available_bytes=(512*1024**2 if low_memory else 2*1024**3))), \
             patch("run_experiment.time.monotonic", side_effect=(lambda:120 if finished.is_set() else 0)) if profile else contextlib.nullcontext(), \
             patch("pipeline.time.sleep"):
            options = (["--profile","local-load-v1","--db-time-offset","+00:00"] if profile else
                       ["--observe-pipeline", "--db-time-offset", "+00:00"] if observe_pipeline else [])
            code = main(["--execute", "--seconds", str(seconds), *options])
        manifest_path = next(root.glob("build/test-runs/*/manifest.json"))
        metrics = json.loads((manifest_path.parent / "metrics.json").read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return code, metrics, manifest

    def test_formal_profile_runs_through_guard_accounting_policy_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            code,metrics,manifest=self.run_fake(root,profile=True,actual_count=120)
            self.assertEqual(code,0)
            self.assertEqual(metrics["performance"]["verdict"],"PASS")
            self.assertFalse(manifest["k6_stop_requested"])
            self.assertEqual(manifest["evaluation_version"],"local-load-v1")
            self.assertEqual(metrics["guard"]["http_samples"],120)
            self.assertTrue(metrics["guard"]["http_stream_complete"])
            self.assertEqual(manifest["drain_seconds"],60)
            self.assertIn("local-load-rps1",manifest["id"])
            import hashlib
            raw=next(root.glob("build/test-runs/*/raw/load-policy.json"))
            self.assertEqual(hashlib.sha256(raw.read_bytes()).hexdigest(),manifest["load_policy_sha256"])
            report=next(root.glob("docs/testing/local/runs/*.md")).read_text(encoding="utf-8")
            self.assertIn("확정 성능 기준·자동 중단",report)
            self.assertNotIn("성능 합격 상한은 아직 정하지 않음",report)

    def test_automatic_403_stop_preserves_evidence_even_without_valid_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            code,metrics,manifest=self.run_fake(root,profile=True,actual_count=120,
                                               point_status=403,broken_json=True)
            self.assertEqual(code,1)
            self.assertEqual(manifest["state"],"ABORTED")
            self.assertEqual(manifest["abort_reason"]["code"],"unexpected_403")
            self.assertTrue(manifest["k6_stop_requested"])
            self.assertTrue(manifest["k6_exit_confirmed"])
            self.assertEqual(metrics["verdict"],"FAIL")
            self.assertTrue(metrics["evidence_sha256"])
            self.assertTrue(any("k6-points" in name for name in metrics["evidence_sha256"]))

    def test_formal_preflight_low_memory_blocks_before_popen(self):
        with tempfile.TemporaryDirectory() as directory:
            code,metrics,manifest=self.run_fake(Path(directory),profile=True,low_memory=True)
            self.assertEqual(code,1)
            self.assertEqual(manifest["state"],"BLOCKED")
            self.assertNotIn("command",manifest)
            self.assertIsNone(metrics["http"]["http_requests"])

    def test_pipeline_option_saves_accounting_lag_evidence_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, metrics, manifest = self.run_fake(root, actual_count=5, seconds=5, observe_pipeline=True)
            self.assertEqual(code, 0)
            self.assertTrue(manifest["observe_pipeline"])
            self.assertEqual(metrics["pipeline"]["verdict"], "PASS")
            self.assertEqual(metrics["pipeline"]["counts"]["saved_logs"], 5)
            self.assertEqual(metrics["pipeline"]["counts"]["ai_handled_without_detection"], 5)
            self.assertEqual(metrics["pipeline"]["latency_ms"]["log_row_to_ai_handled"]["p50_ms"], 500)
            self.assertIn(str(Path("raw") / "pipeline-summary.json"), metrics["evidence_sha256"])
            self.assertTrue(any(s["label"].startswith("during-") for s in metrics["kafka_snapshots"]))
            text = next(root.glob("docs/testing/local/runs/*.md")).read_text(encoding="utf-8")
            self.assertIn("추가 서버 계측 — local-pipeline-v2", text)
            self.assertIn("커밋 시각이 아님", text)
            self.assertIn('"p50_ms": 500.0', text)

    def test_pipeline_preflight_db_failure_never_starts_load(self):
        with tempfile.TemporaryDirectory() as directory:
            code, metrics, manifest = self.run_fake(Path(directory), observe_pipeline=True, db_denied=True)
            self.assertEqual(code, 1)
            self.assertEqual(manifest["state"], "BLOCKED")
            self.assertNotIn("command", manifest)
            self.assertIsNone(metrics["http"]["http_requests"])
            self.assertEqual(metrics["pipeline"]["verdict"], "INCONCLUSIVE")

    def test_complete_run_with_fake_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, metrics, manifest = self.run_fake(root)
            self.assertEqual(code, 0)
            self.assertEqual(metrics["verdict"], "PASS")
            self.assertEqual(manifest["state"], "COMPLETED")
            self.assertEqual(metrics["kafka_snapshots"][0]["rows"][0]["lag"], 0)
            self.assertTrue(metrics["evidence_sha256"])
            self.assertEqual(manifest["evaluation_version"], "arrival-smoke-v3")
            self.assertEqual(metrics["http"]["http_avg_ms"], 10)
            self.assertEqual(metrics["http"]["http_p50_ms"], 8)
            self.assertEqual(metrics["http"]["http_p95_ms"], 25)
            self.assertEqual(metrics["http"]["http_p99_ms"], 40)
            self.assertEqual(metrics["http"]["http_max_ms"], 60)
            report = next(root.glob("docs/testing/local/runs/*.md")).read_text(encoding="utf-8")
            self.assertIn("| http_p50_ms | 8 |", report)
            self.assertIn("| http_p99_ms | 40 |", report)
            self.assertIn("http_avg_ms·http_p50_ms·http_p95_ms", report)
            self.assertIn("http_p99_ms·http_max_ms는 ms", report)
            summary_path = next(root.glob("build/test-runs/*/raw/k6-summary.json"))
            raw_metrics = json.loads(summary_path.read_text(encoding="utf-8"))["results"]["metrics"]
            raw_duration = next(metric for metric in raw_metrics if metric["name"] == "http_req_duration")
            self.assertEqual(raw_duration["values"]["med"], 8)
            self.assertEqual(raw_duration["values"]["p(99)"], 40)

    def test_arrival_run_keeps_plan_and_actual_counts_separate(self):
        # 재현: 1회/초 × 5초 계획이 실제 6회 완료돼도 HTTP 실패로 보지 않는다.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, metrics, manifest = self.run_fake(root, actual_count=6, seconds=5)
            self.assertEqual(code, 0)
            self.assertEqual(metrics["verdict"], "PASS")
            self.assertEqual(manifest["target_count"], 5)
            self.assertEqual(manifest["evaluation_version"], EVALUATION_VERSION)
            self.assertEqual(metrics["http"]["http_requests"], 6)
            self.assertEqual(metrics["http"]["completed_iterations"], 6)
            self.assertEqual(metrics["request_count_delta"], 1)
            report = next(root.glob("docs/testing/local/runs/*.md")).read_text(encoding="utf-8")
            self.assertIn("계획 참고 건수: 5회", report)
            self.assertIn(EVALUATION_VERSION, report)
            self.assertIn("판정 근거:", report)

    def test_failed_run_records_verdict_reasons_even_without_collector_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, metrics, manifest = self.run_fake(root, ok_rate=0.5, exit_code=99)
            self.assertEqual(code, 1)
            self.assertEqual(metrics["verdict"], "FAIL")
            self.assertEqual(manifest["state"], "COMPLETED")
            self.assertTrue(any("HTTP 200" in reason for reason in metrics["verdict_reasons"]))
            report = next(root.glob("docs/testing/local/runs/*.md")).read_text(encoding="utf-8")
            self.assertIn("HTTP 200 응답 비율이 100%가 아닙니다.", report)

    def test_interruption_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            code, metrics, manifest = self.run_fake(Path(directory), interrupted=True)
            self.assertEqual(code, 1)
            self.assertEqual(manifest["state"], "ABORTED")
            self.assertEqual(metrics["verdict"], "INCONCLUSIVE")

    def test_broken_summary_preserves_other_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            code, metrics, manifest = self.run_fake(Path(directory), broken_json=True)
            self.assertEqual(code, 1)
            self.assertIsNone(metrics["http"]["http_requests"])
            self.assertIsNone(metrics["http"]["http_p50_ms"])
            self.assertIsNone(metrics["http"]["http_p99_ms"])
            self.assertEqual(metrics["verdict"], "INCONCLUSIVE")
            self.assertGreater(metrics["docker_samples"], 0)
    def test_lag_zero_and_unknown_are_different(self):
        data = "GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID\n"
        data += "g t 0 10 10 0 c h x\ng t 1 - 10 - c h x\n"
        rows = parse_lag(data)
        self.assertEqual(rows[0]["lag"], 0)
        self.assertIsNone(rows[1]["lag"])
        self.assertEqual(parse_lag("No consumer groups"), [])

    def test_cpu_above_100_is_preserved(self):
        result = resource_peaks([{"containers": [
            {"Name": "ai", "CPUPerc": "180.5%", "MemPerc": "20.0%"}]}])
        self.assertEqual(result["ai"]["cpu_percent_max"], 180.5)
    def test_old_and_new_summary(self):
        metrics = {
            "http_reqs": {"values": {"count": 60}},
            "iterations": {"values": {"count": 60}},
            "http_req_duration": {"values": {"avg": 8, "med": 7, "p(95)": 12.5,
                                             "p(99)": 18.5, "max": 20}},
            "normal_ok": {"values": {"rate": 1}},
            "dropped_iterations": {"values": {"count": 0}},
        }
        new = {"results": {"metrics": [{"name": k, **v} for k, v in metrics.items()]}}
        self.assertEqual(normalize({"metrics": metrics}), normalize(new))
        self.assertEqual(normalize(new)["completed_iterations"], 60)
        self.assertEqual(normalize(new)["http_avg_ms"], 8)
        self.assertEqual(normalize(new)["http_p50_ms"], 7)
        self.assertEqual(normalize(new)["http_p99_ms"], 18.5)
        self.assertEqual(normalize(new)["http_max_ms"], 20)

    def test_old_summary_without_p99_does_not_fabricate_a_percentile(self):
        values = normalize({"metrics": {
            "http_reqs": {"values": {"count": 60}},
            "iterations": {"values": {"count": 60}},
            "http_req_duration": {"values": {"avg": 5, "p(95)": 10, "max": 20}},
            "normal_ok": {"values": {"rate": 1}},
            "dropped_iterations": {"values": {"count": 0}},
        }})
        self.assertIsNone(values["http_p99_ms"])
        self.assertEqual(values["http_p95_ms"], 10)
        decision = assess(values, 0, True)
        self.assertEqual(decision["verdict"], "INCONCLUSIVE")
        self.assertTrue(any("http_p99_ms" in reason for reason in decision["reasons"]))

    def test_invalid_p99_values_are_missing_in_both_summary_formats(self):
        for value in (None, float("nan"), float("inf"), float("-inf"),
                      -1, True, "18.5", {}, []):
            duration = {"values": {"avg": 5, "p(95)": 10, "p(99)": value, "max": 20}}
            for summary in ({"metrics": {"http_req_duration": duration}},
                            {"results": {"metrics": [{"name": "http_req_duration", **duration}]}}):
                with self.subTest(value=value, format=list(summary)):
                    normalized = normalize(summary)
                    self.assertIsNone(normalized["http_p99_ms"])
                    self.assertEqual(normalized["http_p95_ms"], 10)

    def test_invalid_p50_is_missing_in_both_summary_formats(self):
        for value in (None, float("nan"), float("inf"), float("-inf"),
                      -1, True, "7.5", {}, []):
            duration = {"values": {"avg": 5, "med": value, "p(95)": 10}}
            for summary in ({"metrics": {"http_req_duration": duration}},
                            {"results": {"metrics": [{"name": "http_req_duration", **duration}]}}):
                with self.subTest(value=value, format=list(summary)):
                    normalized = normalize(summary)
                    self.assertIsNone(normalized["http_p50_ms"])
                    self.assertEqual(normalized["http_p95_ms"], 10)

    def test_zero_p50_is_a_measurement_not_missing(self):
        values = normalize({"metrics": {"http_req_duration": {"values": {"med": 0}}}})
        self.assertEqual(values["http_p50_ms"], 0)

    def test_missing_or_invalid_reference_p50_preserves_verdict_and_evidence(self):
        for options in ({"include_p50": False}, {"p50": None}, {"p50": "invalid"}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                code, metrics, manifest = self.run_fake(root, **options)
                self.assertEqual(code, 0)
                self.assertEqual(metrics["verdict"], "PASS")
                self.assertEqual(manifest["evaluation_version"], "arrival-smoke-v3")
                self.assertIsNone(metrics["http"]["http_p50_ms"])
                self.assertEqual(metrics["http"]["http_p99_ms"], 40)
                self.assertTrue(metrics["evidence_sha256"])
                report = next(root.glob("docs/testing/local/runs/*.md")).read_text(encoding="utf-8")
                self.assertIn("| http_p50_ms | 미측정 |", report)

    def test_reference_p50_does_not_add_a_performance_limit(self):
        values = dict(http_requests=6, completed_iterations=6,
                      http_avg_ms=2000000, http_p50_ms=1000000,
                      http_p95_ms=3000000, http_p99_ms=4000000,
                      http_max_ms=5000000, normal_ok_rate=1, dropped_iterations=0)
        self.assertEqual(judge(values, 0, True), "PASS")

    def test_zero_p99_is_a_measurement_not_missing(self):
        values = normalize({"metrics": {
            "http_req_duration": {"values": {"avg": 0, "p(95)": 0,
                                             "p(99)": 0, "max": 0}}}})
        self.assertEqual(values["http_p99_ms"], 0)

    def test_missing_null_or_invalid_p99_preserves_run_evidence(self):
        for options in ({"include_p99": False}, {"p99": None}, {"p99": "invalid"}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                code, metrics, manifest = self.run_fake(root, **options)
                self.assertEqual(code, 1)
                self.assertEqual(manifest["state"], "COMPLETED")
                self.assertEqual(metrics["verdict"], "INCONCLUSIVE")
                self.assertEqual(metrics["http"]["http_requests"], 60)
                self.assertIsNone(metrics["http"]["http_p99_ms"])
                self.assertTrue(metrics["evidence_sha256"])
                self.assertTrue(any("http_p99_ms" in reason for reason in metrics["verdict_reasons"]))
                report = next(root.glob("docs/testing/local/runs/*.md")).read_text(encoding="utf-8")
                self.assertIn("| http_p99_ms | 미측정 |", report)

    def test_missing_is_not_zero(self):
        values = normalize({"results": {"metrics": []}})
        self.assertTrue(all(v is None for v in values.values()))
        self.assertEqual(judge(values, 0, True), "INCONCLUSIVE")

    def test_pass_and_fail(self):
        values = dict(http_requests=60, completed_iterations=60,
                      http_avg_ms=5, http_p95_ms=10, http_p99_ms=15,
                      http_max_ms=20, normal_ok_rate=1,
                      dropped_iterations=0)
        self.assertEqual(judge(values, 0, True), "PASS")
        self.assertEqual(judge(values, 0, False), "INCONCLUSIVE")
        self.assertEqual(judge(values, 99, True), "FAIL")
        self.assertEqual(judge({**values, "normal_ok_rate": 0.5}, 0, False), "FAIL")
        self.assertEqual(judge({**values, "http_requests": 59}, 0, True), "FAIL")
        self.assertEqual(judge({**values, "dropped_iterations": 1}, 0, True), "FAIL")

    def test_missing_required_metrics_runtime_error_and_abort_are_inconclusive(self):
        values = dict(http_requests=6, completed_iterations=6,
                      http_avg_ms=5, http_p95_ms=10, http_p99_ms=15, http_max_ms=20,
                      normal_ok_rate=1, dropped_iterations=0)
        for key in ("completed_iterations", "http_avg_ms", "http_p95_ms",
                    "http_p99_ms", "http_max_ms"):
            with self.subTest(missing=key):
                self.assertEqual(judge({**values, key: None}, 0, True), "INCONCLUSIVE")
        self.assertEqual(judge(values, 1, True), "INCONCLUSIVE")
        self.assertEqual(judge(values, 0, True, state="ABORTED"), "INCONCLUSIVE")

    def test_p99_collection_does_not_invent_a_latency_limit(self):
        values = dict(http_requests=6, completed_iterations=6,
                      http_avg_ms=5, http_p95_ms=10, http_p99_ms=1000000,
                      http_max_ms=2000000, normal_ok_rate=1, dropped_iterations=0)
        self.assertEqual(judge(values, 0, True), "PASS")

    def test_no_requests_cannot_pass(self):
        values = dict(http_requests=0, completed_iterations=0,
                      http_p95_ms=None, normal_ok_rate=None, dropped_iterations=0)
        decision = assess(values, 0, True)
        self.assertEqual(decision["verdict"], "FAIL")
        self.assertTrue(any("실제 HTTP 요청이 없습니다" in reason
                            for reason in decision["reasons"]))

    def test_smoke_verdict_is_not_a_rate_attainment_check(self):
        with tempfile.TemporaryDirectory() as directory:
            code, metrics, manifest = self.run_fake(Path(directory), actual_count=59)
            self.assertEqual(code, 0)
            self.assertEqual(metrics["verdict"], "PASS")
            self.assertEqual(manifest["target_count"], 60)
            self.assertEqual(metrics["request_count_delta"], -1)

    def test_nonfinite_data_is_missing(self):
        values = normalize({"metrics": {
            "http_req_duration": {"values": {"p(95)": float("nan")}}}})
        self.assertIsNone(values["http_p95_ms"])

    def test_reject_remote_and_bad_limits(self):
        for args in (["--url", "https://example.com/"], ["--rate", "0"],
                     ["--seconds", "121"], ["--url", "http://127.0.0.1/?token=secret"]):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                arguments(["--dry-run"] + args)

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, report = reserve(root, "test")
            self.assertEqual(output, root / "build/test-runs/test")
            self.assertEqual(report, root / "docs/testing/local/runs/test.md")
            report.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                reserve(root, "test")
            self.assertEqual(report.read_text(encoding="utf-8"), "keep")

    def test_dry_run_never_calls_command_or_reserves(self):
        with patch("run_experiment.command", side_effect=AssertionError("command")), \
             patch("run_experiment.reserve", side_effect=AssertionError("write")):
            self.assertEqual(main(["--dry-run"]), 0)

    def test_blocked_run_writes_files_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("run_experiment.ROOT", root), \
                 patch("run_experiment.tool_versions", side_effect=RuntimeError("missing k6")):
                self.assertEqual(main(["--execute"]), 1)
            manifests = list(root.glob("build/test-runs/*/manifest.json"))
            self.assertEqual(len(manifests), 1)
            manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
            self.assertEqual(manifest["state"], "BLOCKED")
            metrics = json.loads((manifests[0].parent / "metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(metrics["verdict"], "INCONCLUSIVE")
            self.assertIsNone(metrics["http"]["http_requests"])
            self.assertIsNone(metrics["http"]["http_p99_ms"])
            self.assertEqual(len(list(root.glob("docs/testing/local/runs/*.md"))), 1)


if __name__ == "__main__":
    unittest.main()



'''
 - 역할: 외부 서비스 없이 실행·판정·기록을 검증하는 모의 테스트
'''


