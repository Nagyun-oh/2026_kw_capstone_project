import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from collect_ec2_inventory import Collector, env_presence, lag_rows, main, nginx_summary


class Ec2InventoryTests(unittest.TestCase):
    def test_env_reports_only_key_presence_and_does_not_expand_shell(self):
        with patch.object(Path, "read_text", return_value="# MYSQL_ROOT_PASSWORD=comment\nexport DB_PASSWORD='private-value'\n"
                          "PIPELINE_TRACE_ENABLED=false\nOTHER=$(do-not-run)\n"):
            result = env_presence(Path("fixture-env"))
        self.assertTrue(result["keys_present"]["DB_PASSWORD"])
        self.assertFalse(result["keys_present"]["MYSQL_ROOT_PASSWORD"])
        self.assertTrue(result["keys_present"]["PIPELINE_TRACE_ENABLED"])
        self.assertNotIn("private-value", json.dumps(result))
        self.assertNotIn("OTHER", json.dumps(result))

    def test_missing_env_is_unknown_instead_of_empty_keys(self):
        self.assertEqual(env_presence(Path("not-existing-p0-env")), {"readable": False, "keys_present": None})

    def test_nginx_extracts_headers_without_retaining_secrets_or_addresses(self):
        result = nginx_summary("""
more_set_headers 'X-Request-ID: $request_id';
more_set_headers 'X-DualGuard-Request-Start: $dg_request_start_epoch_s';
set_real_ip_from 172.18.0.1;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header Authorization "private-token";
proxy_pass http://127.0.0.1:8081;
""")
        self.assertTrue(result["request_id_response_header_present"])
        self.assertTrue(result["request_start_response_header_present"])
        self.assertEqual(result["upstream_ports"], [8081])
        self.assertEqual(result["trusted_proxy_directive_count"], 1)
        self.assertNotIn("private-token", json.dumps(result))
        self.assertNotIn("172.18.0.1", json.dumps(result))
        self.assertFalse(nginx_summary("# add_header X-Request-ID ignored;\n")["request_id_response_header_present"])

    def test_kafka_zero_and_unknown_are_distinct_and_hosts_are_omitted(self):
        rows = lag_rows("""GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID
log-group log-topic 0 10 10 0 consumer /172.18.0.8 client
ai-service-group ai-request-topic 0 - 7 - consumer /172.18.0.9 client
""")
        self.assertEqual(rows[0]["lag"], 0)
        self.assertIsNone(rows[1]["lag"])
        self.assertNotIn("172.18.", json.dumps(rows))
        self.assertEqual(lag_rows("No groups found"), [])

    def test_failed_commands_do_not_keep_stdout_stderr_or_arguments(self):
        collector = Collector(Path.cwd())
        with patch("collect_ec2_inventory.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "private-output", "private-error")) as run:
            result = collector.run("db", ["fake", "private-arg"], input_text="private-input")
        self.assertIsNone(result)
        self.assertEqual(collector.commands[0]["status"], "COMMAND_FAILED")
        self.assertNotIn("private-", json.dumps(collector.data))
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_timeout_is_preserved_without_including_exception_output(self):
        collector = Collector(Path.cwd())
        with patch("collect_ec2_inventory.subprocess.run", side_effect=subprocess.TimeoutExpired("private-command", 2, output="private-output")):
            self.assertIsNone(collector.run("lag", ["fake"], timeout=2))
        self.assertEqual(collector.commands[0]["status"], "TIMEOUT")
        self.assertNotIn("private-", json.dumps(collector.data))

    def test_db_reads_have_query_deadline_read_only_transaction_and_fallback(self):
        collector = Collector(Path.cwd())
        with patch.object(collector, "docker", side_effect=[None, '{"state":"SENT","count":1}\n']) as docker:
            rows = collector.sql("counts", "container", "SELECT 1;")
        self.assertEqual(rows[0]["count"], 1)
        self.assertEqual(collector.data["database_auth"]["counts"], "root_container_environment")
        for call in docker.call_args_list:
            sql = call.kwargs["input_text"]
            self.assertIn("MAX_EXECUTION_TIME=3000", sql)
            self.assertIn("START TRANSACTION READ ONLY;", sql)
            self.assertTrue(sql.endswith("ROLLBACK;\n"))
            self.assertNotIn("-p", call.args[1])

    def test_missing_outbox_is_not_counted_as_zero_or_queried(self):
        collector = Collector(Path.cwd())
        with patch.object(collector, "sql", return_value=[{"kind": "table", "table": "network_logs"}]) as sql:
            collector.database("container")
        self.assertIsNone(collector.data["outbox_counts"])
        self.assertEqual(sql.call_count, 1)
        schema_query = sql.call_args.args[2]
        self.assertIn("'estimated_rows',TABLE_ROWS", schema_query)
        self.assertNotRegex(schema_query, r"(?i)\b(UPDATE|INSERT|DELETE|ALTER|CREATE|DROP)\b")

    def test_metadata_keeps_only_instance_type_region_and_architecture(self):
        class Response:
            def __init__(self, value):
                self.value = value.encode()

            def read(self):
                return self.value

        collector = Collector(Path.cwd())
        doc = {"instanceType": "t3.large", "instanceId": "i-private", "region": "ap-northeast-2",
               "architecture": "x86_64", "accountId": "private-account", "privateIp": "172.31.1.1"}
        with patch("collect_ec2_inventory.urllib.request.build_opener") as opener:
            opener.return_value.open.side_effect = [Response("private-token"), Response(json.dumps(doc))]
            collector.cloud(False)
        text = json.dumps(collector.data)
        self.assertEqual(collector.data["ec2"]["instance_type"], "t3.large")
        self.assertEqual(collector.data["ec2"]["credits_status"], "NOT_REQUESTED")
        for private in ("private-token", "private-account", "i-private", "172.31.1.1"):
            self.assertNotIn(private, text)

    def test_failed_metadata_does_not_fall_back_to_credentials_or_imdsv1(self):
        collector = Collector(Path.cwd())
        with patch("collect_ec2_inventory.urllib.request.build_opener") as opener:
            opener.return_value.open.side_effect = TimeoutError("private-token")
            collector.cloud(True)
        self.assertEqual(opener.return_value.open.call_count, 1)
        self.assertEqual(collector.data["ec2"]["metadata_status"], "UNAVAILABLE")
        self.assertIsNone(collector.data["ec2"]["credits"])
        self.assertNotIn("private-token", json.dumps(collector.data))

    def test_cli_refuses_local_windows_before_any_commands(self):
        with patch("collect_ec2_inventory.sys.platform", "win32"), patch("collect_ec2_inventory.subprocess.run") as run, patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                main(["--repo", str(Path.cwd())])
        run.assert_not_called()

    def test_incomplete_inventory_cannot_look_complete_when_commands_return_nothing(self):
        collector = Collector(Path.cwd())
        def unavailable_metadata(*args):
            collector.data["ec2"] = {"metadata_status": "UNAVAILABLE", "credits": None}
        with patch.object(collector, "run", return_value=None), patch.object(collector, "host"), \
                patch.object(collector, "cloud", side_effect=unavailable_metadata), \
                patch("collect_ec2_inventory.env_presence", return_value={"readable": False, "keys_present": None}), \
                patch.object(Path, "is_file", return_value=False):
            result = collector.collect()
        self.assertEqual(result["inventory_status"], "COLLECTED_WITH_GAPS")
        self.assertIn("table:ai_request_outbox", result["missing_observations"])
        self.assertIn("lag:ai-result-group/ai-result-topic", result["missing_observations"])
        self.assertIn("runtime_flags", result["missing_observations"])
        self.assertIsNone(result["kafka_lag"])

    def test_container_without_healthcheck_is_kept_and_runtime_flags_are_collected(self):
        collector = Collector(Path.cwd())
        calls = []
        def fake_run(label, argv, **kwargs):
            calls.append(label)
            if label == "project_containers":
                return "abcdef123456\n"
            if label == "container_inspect":
                return json.dumps({"service": "backend", "image": "registry/security-backend:sha", "image_id": "sha256:fake", "health": None, "state": "running"})
            if label == "image_digests":
                return '["registry/security-backend@sha256:fake"]'
            if label.startswith("runtime_"):
                return "true\n"
            return None
        def unavailable_metadata(*args):
            collector.data["ec2"] = {"metadata_status": "UNAVAILABLE", "credits": None}
        with patch.object(collector, "run", side_effect=fake_run), patch.object(collector, "host"), \
                patch.object(collector, "cloud", side_effect=unavailable_metadata), \
                patch("collect_ec2_inventory.env_presence", return_value={"readable": False, "keys_present": None}), \
                patch.object(Path, "is_file", return_value=False):
            result = collector.collect()
        self.assertEqual(len(result["containers"]), 1)
        self.assertIsNone(result["containers"][0]["health"])
        self.assertTrue(result["runtime_flags"]["PIPELINE_TRACE_ENABLED"])
        self.assertIn("runtime_AI_OUTBOX_ENABLED", calls)


if __name__ == "__main__":
    unittest.main()
