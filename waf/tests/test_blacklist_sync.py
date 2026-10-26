"""임시 폴더에서 블랙리스트 동기화 스크립트를 검증한다. Docker와 실제 nginx는 호출하지 않는다.

가짜 백엔드(HTTP 서버)와 호출만 기록하는 가짜 nginx를 사용한다.
장애 재현용으로 지정한 파일의 mv를 한 번 실패시키는 가짜 mv와, reload 뒤 worker 교체를 늦추는 기능을 둔다.
"""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
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
        self.proc = root / "proc"
        real_mv = shutil.which("mv")
        nginx = root / "bin" / "nginx"
        nginx.parent.mkdir()
        # reload가 성공하면 가짜 worker 디렉터리를 새 PID로 바꾼다.
        # 앞의 TEST_NGINX_RELOAD_STALL번은 바꾸지 않아 reload 확인 시간 초과를 재현한다.
        nginx.write_text(
            '#!/bin/sh\n'
            'echo "$*" >> "$TEST_NGINX_CALLS"\n'
            'case "$*" in\n'
            '  -t) [ "${TEST_NGINX_T_FAIL:-0}" = 0 ] || { echo "nginx: [emerg] test rule error" >&2; exit 1; } ;;\n'
            '  "-s reload")\n'
            '    [ "${TEST_NGINX_RELOAD_FAIL:-0}" = 0 ] || { echo "nginx: [alert] reload failed" >&2; exit 1; }\n'
            '    if [ "$(grep -c \'^-s reload$\' "$TEST_NGINX_CALLS")" -gt "${TEST_NGINX_RELOAD_STALL:-0}" ]; then\n'
            '      for dir in "$WAF_PROC_DIR"/[0-9]*; do\n'
            f'        if [ -d "$dir" ]; then {real_mv} "$dir" "${{dir}}0"; fi\n'
            '      done\n'
            '    fi\n'
            '    exit 0 ;;\n'
            '  *) exit 2 ;;\n'
            'esac\n'
        )
        nginx.chmod(0o700)
        # TEST_MV_FAIL_FLAG 파일이 있는 동안 TEST_MV_FAIL_FROM을 옮기는 호출을 한 번 실패시킨다(파일 교체 실패 재현).
        fake_mv = nginx.parent / "mv"
        fake_mv.write_text(
            '#!/bin/sh\n'
            'if [ -n "${TEST_MV_FAIL_FROM:-}" ] && [ "$2" = "$TEST_MV_FAIL_FROM" ] && [ -e "$TEST_MV_FAIL_FLAG" ]; then\n'
            '  rm -f "$TEST_MV_FAIL_FLAG"\n'
            '  echo "mv: cannot move \'$2\': Permission denied" >&2\n'
            '  exit 1\n'
            'fi\n'
            f'exec {real_mv} "$@"\n'
        )
        fake_mv.chmod(0o700)
        self.mv_fail_flag = root / "mv-fail-once"

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

    def state_files(self):
        return sorted(p.name for p in self.state.iterdir())

    def add_worker(self, pid):
        (self.proc / str(pid)).mkdir()
        (self.proc / str(pid) / "cmdline").write_bytes(b"nginx: worker process\0")

    def fail_next_replace(self):
        """다음 번 새 룰(blacklist.conf.new) 교체를 한 번 실패시키는 환경변수."""
        self.mv_fail_flag.touch()
        return dict(TEST_MV_FAIL_FROM=str(self.state / "blacklist.conf.new"),
                    TEST_MV_FAIL_FLAG=str(self.mv_fail_flag))

    def interrupted_apply(self, last_good_ips, candidate_ips):
        """새 룰로 교체한 뒤 nginx -t·reload 전에 종료된 상태를 만든다. 마지막 정상 룰을 돌려준다."""
        self.serve(candidate_ips)
        self.run_sync()
        candidate = self.rules.read_bytes()
        self.serve(last_good_ips)
        self.run_sync()
        last_good = self.rules.read_bytes()
        (self.state / "blacklist.conf.prev").write_bytes(last_good)
        self.rules.write_bytes(candidate)
        self.calls.unlink()
        return last_good

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

    def test_malformed_snapshot_keeps_current_rules(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        applied = self.rules.read_bytes()
        version = "a" * 64
        cases = {
            # 정상 version과 빈 배열이 들어 있어도 JSON 문법이 깨졌으면 차단을 해제하면 안 된다.
            "끝에 쉼표": '{"version":"%s","ipAddresses":[],}' % version,
            "닫는 괄호가 더 있음": '{"version":"%s","ipAddresses":[]}}' % version,
            "쉼표 누락": '{"version":"%s" "ipAddresses":[]}' % version,
            "값이 빠짐": '{"version":"%s","ipAddresses":[],"extra":}' % version,
            "끝이 잘림": '{"version":"%s","ipAddresses":[' % version,
            "객체가 아님": '[{"version":"%s","ipAddresses":[]}]' % version,
            "IP가 숫자": '{"version":"%s","ipAddresses":[1]}' % version,
            "IP에 null": '{"version":"%s","ipAddresses":["198.51.100.7",null]}' % version,
            "IP 목록이 null": '{"version":"%s","ipAddresses":null}' % version,
            "version이 숫자": '{"version":123,"ipAddresses":[]}',
            "빈 본문": "",
        }
        for name, body in cases.items():
            with self.subTest(name):
                self.serve(body=body)
                result = self.run_sync()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("응답 형식이 올바르지 않음", result.stdout)
                self.assertEqual(self.rules.read_bytes(), applied)
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])

    def test_accepts_formatted_snapshot_with_extra_fields(self):
        data = json.loads(snapshot(["203.0.113.10"]))
        data["generatedAt"] = "2026-10-21T00:00:00Z"
        self.serve(body=json.dumps(data, indent=2))
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.blocked_ips(), ["203.0.113.10"])

    def test_replace_failure_keeps_current_rules(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        applied = self.rules.read_bytes()
        self.serve(["198.51.100.7"])
        result = self.run_sync(**self.fail_next_replace())
        self.assertFalse(self.mv_fail_flag.exists(), "교체 실패가 재현되지 않았다")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("룰 파일 교체 실패", result.stdout)
        self.assertEqual(self.rules.read_bytes(), applied)
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"], "교체에 실패하면 검증·reload하지 않는다")
        self.assertEqual(self.state_files(), ["blacklist.conf"])

    def test_replace_failure_is_retried_next_cycle(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        self.serve(["198.51.100.7"])
        env = dict(self.env, WAF_SYNC_INTERVAL="1", **self.fail_next_replace())
        loop = subprocess.Popen(["bash", str(SCRIPT), "run"], env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        self.addCleanup(lambda: loop.poll() is None and os.killpg(loop.pid, signal.SIGKILL))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and self.blocked_ips() != ["198.51.100.7"]:
            time.sleep(0.2)
        os.killpg(loop.pid, signal.SIGTERM)
        output = loop.communicate(timeout=5)[0]
        self.assertFalse(self.mv_fail_flag.exists(), "교체 실패가 재현되지 않았다")
        self.assertIn("룰 파일 교체 실패", output)
        # 실패한 목록의 version을 기억하지 않았으므로 다음 주기에 다시 적용한다.
        self.assertIn("동기화 복구", output)
        self.assertEqual(self.blocked_ips(), ["198.51.100.7"])

    def test_prepare_restores_last_good_rules_after_interrupted_apply(self):
        last_good = self.interrupted_apply(["203.0.113.10"], ["198.51.100.7"])
        result = self.run_sync("prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("마지막 정상 룰로 되돌렸다", result.stdout)
        self.assertEqual(self.rules.read_bytes(), last_good)
        self.assertEqual(self.state_files(), ["blacklist.conf"])
        self.assertEqual(self.nginx_calls(), [])

    def test_sync_reapplies_after_interrupted_apply(self):
        # 교체된 파일이 최신 목록과 같아도 검증·reload를 거치지 않았으므로 다시 적용해야 한다.
        self.interrupted_apply(["203.0.113.10"], ["198.51.100.7"])
        self.serve(["198.51.100.7"])
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("끝나지 않은 이전 적용", result.stdout)
        self.assertEqual(self.blocked_ips(), ["198.51.100.7"])
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])
        self.assertEqual(self.state_files(), ["blacklist.conf"])

    def test_reload_timeout_reapplies_previous_rules(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        applied = self.rules.read_bytes()
        self.add_worker(100)
        self.serve(["198.51.100.7"])
        cases = {
            "이전 룰 reload 성공": ("1", "이전 룰로 다시 reload함"),
            "이전 룰 reload도 시간 초과": ("2", "이전 룰 재적용도 실패"),
        }
        for name, (stalled_reloads, message) in cases.items():
            with self.subTest(name):
                self.calls.unlink(missing_ok=True)
                result = self.run_sync(TEST_NGINX_RELOAD_STALL=stalled_reloads, WAF_RELOAD_TIMEOUT="1")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("reload 실패: 1초 안에 새 worker가 확인되지 않음", result.stdout)
                self.assertIn(message, result.stdout)
                self.assertEqual(self.rules.read_bytes(), applied)
                # 파일만 되돌리지 않고 이전 룰로 다시 검증·reload한다.
                self.assertEqual(self.nginx_calls(), ["-t", "-s reload", "-t", "-s reload"])
                self.assertEqual(self.state_files(), ["blacklist.conf"])

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
