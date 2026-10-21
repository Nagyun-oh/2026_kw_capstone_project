"""임시 폴더에서 블랙리스트 동기화 스크립트를 검증한다. Docker와 실제 nginx는 호출하지 않는다.

가짜 백엔드(HTTP 서버)와 호출만 기록하는 가짜 nginx를 사용한다.
"""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "sync" / "blacklist-sync.sh"
TOKEN = "test-only-sync-token-0123456789abcdef"
RULE_ACTIONS = ("id:20100,phase:1,deny,status:403,log,msg:'Blacklisted IP (backend sync)',"
                "tag:'custom/blacklist',ctl:ruleEngine=On")


def snapshot(ips):
    """백엔드 BlacklistSnapshotService와 같은 방식으로 version을 만든다."""
    unique = sorted(set(ips))
    version = hashlib.sha256("\n".join(unique).encode()).hexdigest()
    return json.dumps({"version": version, "ipAddresses": list(ips)}, separators=(",", ":"))


class FakeBackend(BaseHTTPRequestHandler):
    status = 200
    body = snapshot([])
    tokens = []

    def do_GET(self):
        FakeBackend.tokens.append(self.headers.get("X-WAF-Sync-Token"))
        data = FakeBackend.body.encode()
        self.send_response(FakeBackend.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class BlacklistSyncTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="waf-blacklist-sync-test-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.state = root / "state"
        self.state.mkdir()
        self.rules = self.state / "blacklist.conf"
        (root / "tmp").mkdir()
        # 기본 게이트웨이 172.20.0.1 (리틀 엔디언 16진수 010014AC)
        (root / "proc" / "net").mkdir(parents=True)
        (root / "proc" / "net" / "route").write_text(
            "Iface\tDestination\tGateway\tFlags\n"
            "eth0\t00000000\t010014AC\t0003\n"
            "eth0\t000014AC\t00000000\t0001\n"
        )
        # 실행 중인 nginx 대신 테스트 프로세스 PID를 쓴다.
        self.pid_file = root / "nginx.pid"
        self.pid_file.write_text(str(os.getpid()))
        self.calls = root / "nginx-calls.log"
        nginx = root / "bin" / "nginx"
        nginx.parent.mkdir()
        nginx.write_text(
            '#!/bin/sh\n'
            'echo "$*" >> "$TEST_NGINX_CALLS"\n'
            'case "$*" in\n'
            '  -t) [ "${TEST_NGINX_T_FAIL:-0}" = 0 ] || { echo "nginx: [emerg] test rule error" >&2; exit 1; } ;;\n'
            '  "-s reload") [ "${TEST_NGINX_RELOAD_FAIL:-0}" = 0 ] || { echo "nginx: [alert] reload failed" >&2; exit 1; } ;;\n'
            '  *) exit 2 ;;\n'
            'esac\n'
        )
        nginx.chmod(0o700)

        FakeBackend.status = 200
        FakeBackend.body = snapshot([])
        FakeBackend.tokens = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackend)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

        self.env = {key: value for key, value in os.environ.items() if key != "SET_REAL_IP_FROM"}
        self.env.update(
            PATH=f"{nginx.parent}:{os.environ['PATH']}",
            TMPDIR=str(root / "tmp"),
            TEST_NGINX_CALLS=str(self.calls),
            WAF_BLACKLIST_STATE_DIR=str(self.state),
            WAF_SYNC_URL=f"http://127.0.0.1:{self.server.server_port}/internal/waf/blacklist",
            WAF_SYNC_TOKEN=TOKEN,
            WAF_SYNC_EXCLUDE_IPS="10.9.9.9",
            WAF_PROC_DIR=str(root / "proc"),
            WAF_NGINX_PID_FILE=str(self.pid_file),
        )

    def run_sync(self, mode="once", **extra_env):
        result = subprocess.run(["bash", str(SCRIPT), mode], env=dict(self.env, **extra_env),
                                text=True, capture_output=True, timeout=30)
        self.assertNotIn(TOKEN, result.stdout + result.stderr, "토큰이 로그에 남으면 안 된다")
        return result

    def serve(self, ips=None, status=200, body=None):
        FakeBackend.status = status
        FakeBackend.body = body if body is not None else snapshot(ips or [])

    def nginx_calls(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def blocked_ips(self):
        for line in self.rules.read_text().splitlines():
            if line.startswith("SecRule "):
                return line.split('"@ipMatch ', 1)[1].split('"', 1)[0].split(",")
        return []

    def test_applies_snapshot_and_reloads(self):
        self.serve(["203.0.113.10", "2001:DB8::1"])
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.blocked_ips(), ["203.0.113.10", "2001:db8::1"])
        self.assertIn(f'" "{RULE_ACTIONS}"', self.rules.read_text())
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])
        self.assertEqual(FakeBackend.tokens, [TOKEN])
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), ["blacklist.conf"])

    def test_same_snapshot_is_not_applied_again(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("변경 없음", result.stdout)
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])

    def test_skips_invalid_and_protected_ips(self):
        self.serve([
            "203.0.113.10", "203.0.113.10", "2001:DB8::1", "198.51.100.7",
            "0.0.0.0", "::", "::1", "127.0.0.9", "172.20.0.1", "10.9.9.9", "198.18.0.1",
            "999.1.1.1", "01.2.3.4", "1.2.3.4/24", "abc", "1:2:3:4:5:6:7:8:9", "::ffff:1.2.3.4", "1::2::3",
        ])
        result = self.run_sync(SET_REAL_IP_FROM="198.18.0.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.blocked_ips(), ["203.0.113.10", "2001:db8::1", "198.51.100.7"])
        self.assertIn("IP 형식이 아니어서 제외", result.stdout)
        self.assertIn("172.20.0.1", result.stdout)

    def test_empty_snapshot_removes_existing_block(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        self.serve([])
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.blocked_ips(), [])
        self.assertNotIn("SecRule", self.rules.read_text())
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload", "-t", "-s reload"])
        self.assertIn("해제 [203.0.113.10]", result.stdout)

    def test_fetch_failures_keep_current_rules(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        applied = self.rules.read_bytes()
        cases = {
            "401": dict(status=401, body=""),
            "500": dict(status=500, body="{}"),
            "깨진 JSON": dict(body='{"version":"abc","ipAddresses":["1.2.3.4"]}'),
            "version 없음": dict(body='{"ipAddresses":["1.2.3.4"]}'),
            "배열이 아님": dict(body='{"version":"%s","ipAddresses":"1.2.3.4"}' % ("a" * 64)),
        }
        for name, response in cases.items():
            with self.subTest(name):
                self.serve(**response)
                result = self.run_sync()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("기존 룰 유지", result.stdout)
                self.assertEqual(self.rules.read_bytes(), applied)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        result = self.run_sync(WAF_SYNC_URL=f"http://127.0.0.1:{closed_port}/internal/waf/blacklist")
        self.assertEqual(result.returncode, 1)
        self.assertIn("연결 실패", result.stdout)
        self.assertEqual(self.rules.read_bytes(), applied)
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])

    def test_nginx_test_failure_restores_previous_rules(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        applied = self.rules.read_bytes()
        self.serve(["198.51.100.7"])
        result = self.run_sync(TEST_NGINX_T_FAIL="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("nginx -t 실패", result.stdout)
        self.assertEqual(self.rules.read_bytes(), applied)
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload", "-t"])
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), ["blacklist.conf"])

    def test_reload_failure_restores_previous_rules(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        applied = self.rules.read_bytes()
        self.serve(["198.51.100.7"])
        result = self.run_sync(TEST_NGINX_RELOAD_FAIL="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("reload 실패", result.stdout)
        self.assertEqual(self.rules.read_bytes(), applied)

    def test_writes_rules_without_reload_before_nginx_starts(self):
        self.pid_file.unlink()
        self.serve(["203.0.113.10"])
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.blocked_ips(), ["203.0.113.10"])
        self.assertEqual(self.nginx_calls(), ["-t"])

    def test_prepare_keeps_valid_rules_and_disables_broken_ones(self):
        result = self.run_sync("prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.blocked_ips(), [])

        valid = f'# saved\nSecRule REMOTE_ADDR "@ipMatch 203.0.113.10,2001:db8::1" "{RULE_ACTIONS}"\n'
        self.rules.write_text(valid)
        result = self.run_sync("prepare")
        self.assertIn("마지막 정상 룰로 시작", result.stdout)
        self.assertEqual(self.rules.read_text(), valid)

        broken = 'SecRule REMOTE_ADDR "@ipMatch 999.1.1.1" "id:1,deny"\n'
        self.rules.write_text(broken)
        result = self.run_sync("prepare")
        self.assertIn("형식이 올바르지 않아", result.stdout)
        self.assertEqual((self.state / "blacklist.conf.invalid").read_text(), broken)
        self.assertEqual(self.blocked_ips(), [])
        self.assertEqual(self.nginx_calls(), [], "prepare는 nginx를 호출하지 않는다")

    def test_missing_token_does_not_touch_rules(self):
        self.serve(["203.0.113.10"])
        result = self.run_sync(WAF_SYNC_TOKEN="")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.rules.exists())
        self.assertEqual(FakeBackend.tokens, [])


if __name__ == "__main__":
    unittest.main()
