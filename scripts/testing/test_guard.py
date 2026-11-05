from datetime import datetime, timedelta, timezone
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from guard import (AutoStopGuard, AutomaticStop, PointReader, StopRules,
                   stop_load, valid_memory, wait_for_load)
from load_policy import PROFILE, assess_performance, load_policy
from run_experiment import arguments, main


def point(status=200, seconds=0):
    at = datetime(2026, 11, 1, tzinfo=timezone.utc)+timedelta(seconds=seconds)
    return dict(at=at.isoformat(), status=status, duration_ms=5)


def encoded_point(status=200, seconds=0):
    sample = point(status, seconds)
    return json.dumps(dict(type="Point", metric="http_req_duration",
        data=dict(time=sample["at"], value=sample["duration_ms"], tags=dict(status=str(status)))))+"\n"


def states(policy):
    return {name: dict(id="id-"+name, service=name, running=True, oom_killed=False,
                      restart_count=0, started_at="2026-11-01T00:00:00Z")
            for name in policy["required_services"]}


def result_data():
    http = dict(http_requests=120, http_p95_ms=200, http_p99_ms=500)
    pipeline = dict(counts=dict(saved_logs=120, distinct_request_ids=120, ai_handled_logs=120),
        latency_ms=dict(log_row_to_ai_handled=dict(count=120, p95_ms=2000, p99_ms=5000)),
        final_lag_zero=True, post_load_zero_lag_confirmed_at="2026-11-01T00:03:00Z")
    return http, pipeline


def assess(policy, http, pipeline, abort=None):
    return assess_performance(policy,http,pipeline,abort,load_elapsed=120)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.digest = load_policy()

    def test_frozen_policy_and_source_hash(self):
        self.assertEqual(self.digest, hashlib.sha256(PROFILE.read_bytes()).hexdigest())
        self.assertEqual(self.policy["rates"], [1, 3, 5])
        self.assertEqual(self.policy["seconds"], 120)
        self.assertEqual(self.policy["repetitions_per_rate"], 3)
        self.assertEqual(self.policy["stop"]["min_available_memory_bytes"], 1024**3)

    def test_threshold_equality_passes_and_excess_fails(self):
        http, pipeline = result_data()
        self.assertEqual(assess(self.policy, http, pipeline)["verdict"], "PASS")
        for key in ("http_p95_ms", "http_p99_ms"):
            with self.subTest(key=key):
                changed = {**http, key:http[key]+.01}
                self.assertEqual(assess(self.policy, changed, pipeline)["verdict"], "FAIL")
        for key in ("p95_ms", "p99_ms"):
            with self.subTest(key=key):
                changed = copy.deepcopy(pipeline)
                changed["latency_ms"]["log_row_to_ai_handled"][key] += .01
                self.assertEqual(assess(self.policy, http, changed)["verdict"], "FAIL")

    def test_missing_invalid_or_incomplete_latency_is_inconclusive(self):
        http, pipeline = result_data()
        for value in (None, True, float("nan"), float("inf"), -1, "5"):
            with self.subTest(value=value):
                self.assertEqual(assess(self.policy, {**http, "http_p99_ms":value}, pipeline)["verdict"], "INCONCLUSIVE")
        pipeline["latency_ms"]["log_row_to_ai_handled"]["count"] = 119
        self.assertEqual(assess(self.policy, http, pipeline)["verdict"], "INCONCLUSIVE")

    def test_final_known_backlog_and_db_mismatch_fail(self):
        http, pipeline = result_data()
        pipeline["final_lag_zero"] = False
        self.assertEqual(assess(self.policy, http, pipeline)["verdict"], "FAIL")
        pipeline["final_lag_zero"] = True
        pipeline["counts"]["saved_logs"] = 119
        self.assertEqual(assess(self.policy, http, pipeline)["verdict"], "FAIL")

    def test_unknown_receipt_and_resource_limit_do_not_claim_data_loss(self):
        http, pipeline = result_data()
        pipeline["counts"]["ai_handled_logs"] = 119
        self.assertEqual(assess(self.policy, http, pipeline)["verdict"], "INCONCLUSIVE")
        http, pipeline = result_data()
        abort = dict(verdict="INCONCLUSIVE", reason="host memory")
        self.assertEqual(assess(self.policy, http, pipeline, abort)["verdict"], "INCONCLUSIVE")
        http["http_p95_ms"] = 201
        self.assertEqual(assess(self.policy, http, pipeline, abort)["verdict"], "FAIL")

    def test_cancelled_partial_snapshot_is_not_a_completed_deadline_failure(self):
        http,pipeline=result_data()
        pipeline.update(final_observation_cancelled=True,final_lag_zero=False,
                        post_load_zero_lag_confirmed_at=None)
        pipeline["counts"]["saved_logs"]=10
        result=assess(self.policy,http,pipeline,dict(reason="host memory",verdict="INCONCLUSIVE"))
        self.assertEqual(result["verdict"],"INCONCLUSIVE")

    def test_short_or_unknown_execution_cannot_pass_formal_measurement(self):
        http,pipeline=result_data()
        for elapsed in (None,0,119.99):
            with self.subTest(elapsed=elapsed):
                self.assertEqual(assess_performance(self.policy,http,pipeline,load_elapsed=elapsed)["verdict"],"INCONCLUSIVE")

    def test_profile_defaults_and_dry_run_have_no_service_or_file_side_effects(self):
        args = arguments(["--dry-run", "--profile", "local-load-v1", "--db-time-offset", "+09:00"])
        self.assertEqual((args.seconds,args.drain_seconds,args.observe_pipeline,args.url),
                         (120,60,True,"http://localhost/"))
        with contextlib.redirect_stdout(io.StringIO()) as text, \
             patch("run_experiment.command", side_effect=AssertionError("external command")), \
             patch("run_experiment.reserve", side_effect=AssertionError("write")):
            self.assertEqual(main(["--dry-run", "--profile", "local-load-v1", "--db-time-offset", "+09:00"]), 0)
            self.assertIn("local-load-rps1", text.getvalue())

    def test_profile_cannot_silently_change_fixed_conditions(self):
        for change in (["--seconds","10"], ["--drain-seconds","30"], ["--rate","2"],
                       ["--interval","1"], ["--lag-interval","5"], ["--url","http://127.0.0.1/"]):
            with self.subTest(change=change), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                arguments(["--dry-run","--profile","local-load-v1","--db-time-offset","+09:00",*change])


class StopRuleTests(unittest.TestCase):
    def setUp(self):
        self.policy,_ = load_policy()
        self.rules = StopRules(self.policy)

    def test_403_stops_without_waiting_for_minimum_samples(self):
        self.rules.http(point(403))
        self.assertEqual(self.rules.abort["code"], "unexpected_403")
        self.assertEqual(self.rules.abort["verdict"], "FAIL")

    def test_ten_percent_requires_ten_completed_responses(self):
        self.rules.http(point(0))
        for i in range(1,9):
            self.rules.http(point(200,i))
        self.assertIsNone(self.rules.abort)
        self.rules.http(point(200,9))
        self.assertEqual(self.rules.abort["code"], "http_error_rate")
        self.assertEqual(self.rules.abort["evidence"]["errors"],1)

    def test_old_errors_leave_the_time_window(self):
        self.rules.http(point(500))
        for i in range(10):
            self.rules.http(point(200,20+i*.5))
        self.assertIsNone(self.rules.abort)

    def test_memory_needs_sustained_low_samples_and_resets_after_recovery(self):
        low=dict(total_bytes=4*1024**3, available_bytes=1024**3-1)
        high={**low,"available_bytes":1024**3}
        self.rules.memory(low,0)
        self.rules.memory(low,14.9)
        self.assertIsNone(self.rules.abort)
        self.rules.memory(high,15)
        self.rules.memory(low,20)
        self.rules.memory(low,34.9)
        self.assertIsNone(self.rules.abort)
        self.rules.memory(low,35)
        self.assertEqual(self.rules.abort["code"],"host_memory")
        self.assertEqual(self.rules.abort["verdict"],"INCONCLUSIVE")

    def test_collection_failure_counts_are_per_source_and_reset_on_success(self):
        self.rules.collected("a",False)
        self.rules.collected("b",False)
        self.assertIsNone(self.rules.abort)
        self.rules.collected("a",True)
        self.rules.collected("a",False)
        self.assertIsNone(self.rules.abort)
        self.rules.collected("a",False)
        self.assertEqual(self.rules.abort["code"],"collection_failure")

    def test_actual_violation_is_preserved_after_unknown_stop(self):
        self.rules.trip("collection_failure","missing","INCONCLUSIVE",{})
        self.rules.http(point(403))
        self.assertEqual(self.rules.abort["verdict"],"FAIL")
        self.assertEqual(self.rules.abort["first_stop"]["code"],"collection_failure")

    def test_container_stop_oom_restart_and_replacement_are_detected(self):
        baseline=states(self.policy)
        for change in (dict(running=False),dict(oom_killed=True),dict(restart_count=1),
                       dict(started_at="2026-11-01T01:00:00Z"),dict(id="new-id")):
            with self.subTest(change=change):
                rules=StopRules(self.policy)
                current=copy.deepcopy(baseline)
                current["ai"].update(change)
                rules.containers(current,baseline)
                self.assertEqual(rules.abort["code"],"container_state")
        self.rules.containers(baseline,baseline)
        self.assertIsNone(self.rules.abort)

    def test_invalid_memory_is_not_treated_as_zero(self):
        self.assertFalse(valid_memory(dict(total_bytes=4,available_bytes=True)))
        self.rules.memory(dict(total_bytes=4),0)
        self.rules.memory(dict(total_bytes=4),5)
        self.assertEqual(self.rules.abort["code"],"collection_failure")


class ReaderAndProcessTests(unittest.TestCase):
    def test_partial_json_is_buffered_and_each_point_read_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"points"
            line=encoded_point()
            path.write_text(line[:30],encoding="utf-8")
            reader=PointReader(path)
            self.assertEqual(list(reader.read()),[])
            with path.open("a",encoding="utf-8") as stream:
                stream.write(line[30:])
            self.assertEqual(len(list(reader.read())),1)
            self.assertEqual(list(reader.read()),[])

    def test_metric_metadata_is_ignored_and_corruption_remains_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"points"
            path.write_text('{"type":"Metric","metric":"http_req_duration"}\n'+encoded_point(403)+'broken\n',encoding="utf-8")
            reader=PointReader(path)
            parsed=reader.read()
            self.assertEqual(next(parsed)["status"],403)
            with self.assertRaises(ValueError):
                list(parsed)
            with self.assertRaises(ValueError):
                list(reader.read())

    def test_wait_stops_when_guard_signals_and_does_not_wait_full_duration(self):
        process=Mock()
        guard=Mock(abort=dict(reason="stop"))
        with self.assertRaises(AutomaticStop):
            wait_for_load(process,guard,160)
        process.poll.assert_not_called()

    def test_stop_load_only_signals_created_process_and_falls_back(self):
        process=Mock()
        process.poll.return_value=None
        process.send_signal.side_effect=OSError("no console")
        process.wait.side_effect=[subprocess.TimeoutExpired("k6",5),0]
        stop_load(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()


class GuardPreflightTests(unittest.TestCase):
    def test_preflight_records_only_selected_container_and_memory_fields(self):
        policy,_=load_policy()
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)
            (output/"raw").mkdir()
            command=Mock(return_value=dict(code=0,stdout="\n".join(json.dumps(r) for r in states(policy).values())))
            guard=AutoStopGuard(policy,output,["docker","compose"],["id"],command,Mock(),
                memory_provider=lambda:dict(total_bytes=8*1024**3,available_bytes=2*1024**3))
            guard.preflight()
            self.assertTrue((output/"raw/guard-preflight.json").is_file())
            self.assertNotIn(".Config.Env",command.call_args.args[0][3])

    def test_preflight_refuses_already_low_host_memory(self):
        policy,_=load_policy()
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)
            (output/"raw").mkdir()
            command=Mock(return_value=dict(code=0,stdout="\n".join(json.dumps(r) for r in states(policy).values())))
            guard=AutoStopGuard(policy,output,["docker","compose"],["id"],command,Mock(),
                memory_provider=lambda:dict(total_bytes=8*1024**3,available_bytes=1024**3-1))
            with self.assertRaises(RuntimeError):
                guard.preflight()
            saved=json.loads((output/"raw/guard-preflight.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["memory"]["available_bytes"],1024**3-1)


if __name__=="__main__":
    unittest.main()
