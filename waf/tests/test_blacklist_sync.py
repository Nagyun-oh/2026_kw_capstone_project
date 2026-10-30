"""임시 폴더에서 블랙리스트 동기화 스크립트를 검증한다. Docker와 실제 nginx는 호출하지 않는다.

가짜 백엔드(HTTP 서버)와 호출만 기록하는 가짜 nginx를 사용한다. 가짜 백엔드는 스냅샷 조회(GET)와
상태 보고(POST /internal/waf/sync-status)를 받는다. 실제 백엔드 보고 API가 아직 없어 보고 형식은
docs/waf-sync-status-api.md 초안을 기준으로 검증한다.
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
HOOK = SCRIPT.with_name("99-blacklist-sync.sh")
TOKEN = "test-only-sync-token-0123456789abcdef"
RULE_ACTIONS = ("id:20100,phase:1,deny,status:403,log,msg:'Blacklisted IP (backend sync)',"
                "tag:'custom/blacklist',ctl:ruleEngine=On")


def version_of(ips):
    """백엔드 BlacklistSnapshotService와 같은 방식으로 version을 만든다."""
    return hashlib.sha256("\n".join(sorted(set(ips))).encode()).hexdigest()


def snapshot(ips):
    return json.dumps({"version": version_of(ips), "ipAddresses": list(ips)}, separators=(",", ":"))


class FakeBackend(BaseHTTPRequestHandler):
    status = 200
    body = snapshot([])
    tokens = []
    report_status = 204
    reports = []          # 받은 상태 보고(경로·헤더·본문)
    report_hold = None    # threading.Event면 보고에 응답하기 전에 기다린다(응답 지연 재현)

    def do_POST(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        FakeBackend.reports.append(dict(
            path=self.path,
            token=self.headers.get("X-WAF-Sync-Token"),
            content_type=self.headers.get("Content-Type"),
            body=json.loads(data),
        ))
        if FakeBackend.report_hold is not None:
            FakeBackend.report_hold.wait(10)
        self.send_response(FakeBackend.report_status)
        self.send_header("Content-Length", "0")
        self.end_headers()

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
        self.runtime_rules = root / "runtime.conf"
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
            '    cp "$WAF_BLACKLIST_STATE_DIR/blacklist.conf" "$TEST_RUNTIME_RULES" || exit 1\n'
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
            'if { [ -n "${TEST_MV_FAIL_FROM:-}" ] && [ "$2" = "$TEST_MV_FAIL_FROM" ]; } ||\n'
            '   { [ -n "${TEST_MV_FAIL_TO:-}" ] && [ "$3" = "$TEST_MV_FAIL_TO" ]; }; then\n'
            '  if [ -e "$TEST_MV_FAIL_FLAG" ]; then\n'
            '  rm -f "$TEST_MV_FAIL_FLAG"\n'
            '  echo "mv: cannot move \'$2\': Permission denied" >&2\n'
            '  exit 1\n'
            '  fi\n'
            'fi\n'
            f'exec {real_mv} "$@"\n'
        )
        fake_mv.chmod(0o700)
        self.mv_fail_flag = root / "mv-fail-once"
        # 실행 중인 nginx처럼 worker 하나를 둔다. reload 확인은 worker가 바뀌었는지로 판단한다.
        self.add_worker(100)

        FakeBackend.status = 200
        FakeBackend.body = snapshot([])
        FakeBackend.tokens = []
        FakeBackend.report_status = 204
        FakeBackend.reports = []
        FakeBackend.report_hold = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackend)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

        self.env = {key: value for key, value in os.environ.items() if key != "SET_REAL_IP_FROM"}
        self.env.update(
            PATH=f"{nginx.parent}:{os.environ['PATH']}",
            TMPDIR=str(root / "tmp"),
            TEST_NGINX_CALLS=str(self.calls),
            TEST_RUNTIME_RULES=str(self.runtime_rules),
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

    def start_loop(self, **extra_env):
        """1초 간격 동기화·보고 루프(run)를 띄운다."""
        loop = subprocess.Popen(["bash", str(SCRIPT), "run"], env=dict(self.env, WAF_SYNC_INTERVAL="1", **extra_env),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        self.addCleanup(lambda: loop.poll() is None and os.killpg(loop.pid, signal.SIGKILL))
        return loop

    def stop_loop(self, loop):
        os.killpg(loop.pid, signal.SIGTERM)
        output = loop.communicate(timeout=5)[0]
        self.assertNotIn(TOKEN, output, "토큰이 로그에 남으면 안 된다")
        return output

    def wait_for(self, condition, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return True
            time.sleep(0.1)
        return False

    def wait_for_report(self, condition, timeout=15):
        """조건에 맞는 첫 보고 본문을 돌려준다."""
        found = []
        def check():
            found[:] = [r["body"] for r in FakeBackend.reports if condition(r["body"])][:1]
            return bool(found)
        self.assertTrue(self.wait_for(check, timeout),
                        f"조건에 맞는 보고가 없다: {[r['body'] for r in FakeBackend.reports]}")
        return found[0]

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
        self.assertEqual(FakeBackend.reports, [], "once는 상태를 보고하지 않는다")

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
        self.assertIn("172.20.0.1(GATEWAY)", result.stdout)
        # 보호 대상과 지원하지 않는 형식을 모두 보고용 주석에 남긴다.
        self.assertEqual([line for line in self.rules.read_text().splitlines() if line.startswith("# 차단 제외: ")], [
            "# 차단 제외: 0.0.0.0 UNSPECIFIED_ADDRESS",
            "# 차단 제외: :: UNSPECIFIED_ADDRESS",
            "# 차단 제외: ::1 LOOPBACK",
            "# 차단 제외: 127.0.0.9 LOOPBACK",
            "# 차단 제외: 172.20.0.1 GATEWAY",
            "# 차단 제외: 10.9.9.9 CONFIGURED_EXCLUSION",
            "# 차단 제외: 198.18.0.1 TRUSTED_PROXY",
            "# 차단 제외: 999.1.1.1 INVALID_FORMAT",
            "# 차단 제외: 01.2.3.4 INVALID_FORMAT",
            "# 차단 제외: 1.2.3.4/24 INVALID_FORMAT",
            "# 차단 제외: abc INVALID_FORMAT",
            "# 차단 제외: 1:2:3:4:5:6:7:8:9 INVALID_FORMAT",
            "# 차단 제외: ::ffff:1.2.3.4 INVALID_FORMAT",
            "# 차단 제외: 1::2::3 INVALID_FORMAT",
        ])

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
        loop = self.start_loop(**self.fail_next_replace())
        # 보고는 적용·로그가 끝난 뒤에 보내므로 SUCCESS 보고까지 기다린다.
        self.wait_for_report(lambda r: r["appliedVersion"] == version_of(["198.51.100.7"]))
        output = self.stop_loop(loop)
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
        self.assertEqual(self.state_files(), ["blacklist.conf", "blacklist.conf.prev"])
        self.assertEqual(self.nginx_calls(), [])
        self.serve(status=503, body="{}")
        result = self.run_sync()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("HTTP 503", result.stdout)
        self.assertEqual(self.runtime_rules.read_bytes(), last_good)
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])
        self.assertEqual(self.state_files(), ["blacklist.conf"])

    def test_prepare_rejects_invalid_backup_without_clearing_rules(self):
        """복원된 백업이 손상됐으면 빈 목록으로 조용히 시작하지 않는다."""
        self.interrupted_apply(["203.0.113.10"], ["198.51.100.7"])
        backup = self.state / "blacklist.conf.prev"
        backup.write_text("invalid rule\n")
        result = self.run_sync("prepare")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("복원된 마지막 정상 룰의 형식이 올바르지 않다", result.stdout)
        self.assertEqual(backup.read_text(), "invalid rule\n")
        self.assertEqual(self.rules.read_bytes(), backup.read_bytes())
        self.assertNotIn("차단 없이 시작", result.stdout)
        self.assertEqual(self.nginx_calls(), [])

    def test_sync_reapplies_after_interrupted_apply(self):
        # 교체된 파일이 최신 목록과 같아도 검증·reload를 거치지 않았으므로 다시 적용해야 한다.
        self.interrupted_apply(["203.0.113.10"], ["198.51.100.7"])
        self.serve(["198.51.100.7"])
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("끝나지 않은 이전 적용", result.stdout)
        self.assertEqual(self.blocked_ips(), ["198.51.100.7"])
        # 백엔드 조회 전에 이전 룰을 복구하고, 조회에 성공하면 새 룰을 적용한다.
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload", "-t", "-s reload"])
        self.assertEqual(self.state_files(), ["blacklist.conf"])

    def test_interrupted_apply_recovers_runtime_before_failed_fetch(self):
        """새 룰 reload 후 중단되고 백엔드까지 503이어도 이전 실행 설정을 복구한다."""
        last_good = self.interrupted_apply(["203.0.113.10"], ["198.51.100.7"])
        self.runtime_rules.write_bytes(self.rules.read_bytes())
        self.serve(status=503, body="{}")
        result = self.run_sync()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("HTTP 503", result.stdout)
        self.assertEqual(self.rules.read_bytes(), last_good)
        self.assertEqual(self.runtime_rules.read_bytes(), last_good)
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])
        self.assertEqual(self.state_files(), ["blacklist.conf"])

    def test_recovery_failure_keeps_backup_and_retries_after_process_restart(self):
        """복구 검증·reload 실패 시 백업을 보존하고 새 프로세스에서도 복구를 재시도한다."""
        cases = {
            "검증 실패": dict(TEST_NGINX_T_FAIL="1"),
            "신호 실패": dict(TEST_NGINX_RELOAD_FAIL="1"),
            "확인 시간 초과": dict(TEST_NGINX_RELOAD_STALL="100", WAF_RELOAD_TIMEOUT="1"),
        }
        for name, env in cases.items():
            with self.subTest(name):
                last_good = self.interrupted_apply(["203.0.113.10"], ["198.51.100.7"])
                self.runtime_rules.write_bytes(self.rules.read_bytes())
                FakeBackend.tokens.clear()
                self.serve(status=503, body="{}")
                result = self.run_sync(**env)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertEqual((self.state / "blacklist.conf.prev").read_bytes(), last_good)
                self.assertEqual(FakeBackend.tokens, [], "복구 실패 중에는 새 목록을 조회하지 않는다")
                self.calls.unlink()
                # run_sync는 매번 새 프로세스다. 메모리 상태 없이도 백업을 보고 재시도해야 한다.
                retry = self.run_sync()
                self.assertEqual(retry.returncode, 1, retry.stdout)
                self.assertIn("HTTP 503", retry.stdout)
                self.assertEqual(self.runtime_rules.read_bytes(), last_good)
                self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])
                self.assertEqual(self.state_files(), ["blacklist.conf"])

    def test_prepare_restore_failure_returns_error_without_accepting_candidate(self):
        """백업 복원 실패는 정상 준비 완료로 처리하지 않으며 백업을 보존한다."""
        last_good = self.interrupted_apply(["203.0.113.10"], ["198.51.100.7"])
        self.mv_fail_flag.touch()
        result = self.run_sync("prepare",
                               TEST_MV_FAIL_TO=str(self.rules),
                               TEST_MV_FAIL_FLAG=str(self.mv_fail_flag))
        self.assertFalse(self.mv_fail_flag.exists(), "복원 파일 교체 실패가 재현되어야 한다")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("마지막 정상 룰로 시작한다", result.stdout)
        self.assertEqual((self.state / "blacklist.conf.prev").read_bytes(), last_good)
        self.assertEqual(self.nginx_calls(), [])
        retry = self.run_sync("prepare")
        self.assertEqual(retry.returncode, 0, retry.stdout)
        self.assertEqual(self.rules.read_bytes(), last_good)

    def test_startup_hook_stops_when_prepare_fails(self):
        """prepare 실패를 시작 훅이 전파하고 동기화 루프를 시작하지 않는다."""
        bin_dir = self.state.parent / "bin"
        hook_calls = self.state.parent / "hook-calls.log"
        fake_bash = bin_dir / "bash"
        fake_bash.write_text('#!/bin/sh\nprintf "%s\\n" "$2" >> "$TEST_HOOK_CALLS"\nexit 17\n')
        fake_bash.chmod(0o700)
        fake_setsid = bin_dir / "setsid"
        fake_setsid.write_text('#!/bin/sh\necho run >> "$TEST_HOOK_CALLS"\n')
        fake_setsid.chmod(0o700)
        result = subprocess.run(["sh", str(HOOK)], env=dict(self.env, TEST_HOOK_CALLS=str(hook_calls)),
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(hook_calls.read_text().splitlines(), ["prepare"])

    def test_reload_timeout_reapplies_previous_rules(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        applied = self.rules.read_bytes()
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
                expected = ["blacklist.conf"] if stalled_reloads == "1" else ["blacklist.conf", "blacklist.conf.prev"]
                self.assertEqual(self.state_files(), expected)

    def test_reload_is_not_sent_when_workers_are_not_visible(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        applied = self.rules.read_bytes()
        shutil.rmtree(self.proc / "1000")   # reload로 바뀐 worker
        self.calls.unlink()
        self.serve(["198.51.100.7"])
        result = self.run_sync()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("nginx worker를 찾지 못해 적용을 확인할 수 없음", result.stdout)
        self.assertEqual(self.rules.read_bytes(), applied)
        self.assertEqual(self.nginx_calls(), ["-t"], "확인할 수 없는 reload는 보내지 않는다")

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

    def test_prepare_preserves_pending_recovery_until_runtime_is_verified(self):
        # 복구 시간 초과 뒤 prepare만으로는 실행 설정 복구를 완료했다고 판단하지 않는다.
        self.serve(["203.0.113.10"])
        self.run_sync()
        self.calls.unlink()
        self.serve(["198.51.100.7"])
        self.run_sync(TEST_NGINX_RELOAD_STALL="2", WAF_RELOAD_TIMEOUT="1")
        backup = self.state / "blacklist.conf.prev"
        self.assertTrue(backup.exists())
        # 이전 버전에서 만들어진 미확인 표시도 성공한 복구 후에만 지운다.
        marker = Path(self.env["TMPDIR"]) / "waf-blacklist-sync.unverified"
        marker.touch()
        self.run_sync("prepare")
        self.assertTrue(marker.exists())
        self.assertTrue(backup.exists())
        self.serve(["203.0.113.10"])
        self.calls.unlink()
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("변경 없음", result.stdout)
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])
        self.assertFalse(marker.exists())
        self.assertFalse(backup.exists())

    # ------------------------------------------------------------ 상태 보고

    def test_invalid_format_exclusions_preserve_original_strings_after_restart(self):
        invalid = ["01.2.3.4", "::ffff:192.0.2.10", 'bad "ip" \\ value',
                   "(백엔드 version " + "a" * 64 + ")", ""]
        self.serve(["203.0.113.10", *invalid, "01.2.3.4", ""])
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.blocked_ips(), ["203.0.113.10"])
        # 조회에 실패해도 저장된 메타데이터에서 모든 제외 사유를 정확히 읽어야 한다.
        self.serve(status=503, body="{}")
        loop = self.start_loop()
        report = self.wait_for_report(lambda r: r["lastSyncResult"] == "FAILURE")
        self.stop_loop(loop)
        self.assertEqual(report["appliedVersion"], version_of(["203.0.113.10", *invalid]))
        self.assertEqual(report["excludedIps"], [{"ip": ip, "reason": "INVALID_FORMAT"} for ip in invalid])

    def test_pending_recovery_reports_failure_then_confirmed_previous_version(self):
        ips_a = ["203.0.113.10", "172.20.0.1"]
        old = self.interrupted_apply(ips_a, ["198.51.100.7"])
        self.runtime_rules.write_bytes(self.rules.read_bytes())
        self.serve(status=503, body="{}")
        loop = self.start_loop(TEST_NGINX_T_FAIL="1")
        failure = self.wait_for_report(lambda r: r["lastSyncResult"] == "FAILURE")
        self.stop_loop(loop)
        self.assertIsNone(failure["attemptedVersion"])
        self.assertIsNone(failure["appliedVersion"])
        self.assertIsNone(failure["excludedIps"])
        self.assertEqual(failure["error"]["code"], "NGINX_TEST_FAILED")
        self.assertTrue((self.state / "blacklist.conf.prev").exists())
        FakeBackend.reports = []
        # 새 프로세스에서 복구가 성공하면, 조회가 503이어도 확인된 A와 A의 제외 목록을 보고한다.
        loop = self.start_loop()
        recovered = self.wait_for_report(lambda r: r["appliedVersion"] == version_of(ips_a))
        self.stop_loop(loop)
        self.assertEqual(recovered["lastSyncResult"], "FAILURE")
        self.assertIsNone(recovered["attemptedVersion"])
        self.assertEqual(recovered["error"]["code"], "SNAPSHOT_FETCH_FAILED")
        self.assertEqual(recovered["excludedIps"], [{"ip": "172.20.0.1", "reason": "GATEWAY"}])
        self.assertEqual(self.runtime_rules.read_bytes(), old)
        self.assertFalse((self.state / "blacklist.conf.prev").exists())

    def test_legacy_rules_without_exclusion_metadata_are_not_reported_as_complete(self):
        ips = ["203.0.113.10", "172.20.0.1"]
        self.serve(ips)
        self.run_sync()
        self.rules.write_text("\n".join(line for line in self.rules.read_text().splitlines()
                                        if not line.startswith("# 차단 제외")) + "\n")
        self.serve(status=503, body="{}")
        loop = self.start_loop()
        report = self.wait_for_report(lambda r: r["lastSyncResult"] == "FAILURE")
        self.stop_loop(loop)
        self.assertIsNone(report["appliedVersion"])
        self.assertIsNone(report["excludedIps"])
        self.serve(ips)
        loop = self.start_loop()
        report = self.wait_for_report(lambda r: r["lastSyncResult"] == "SUCCESS")
        self.stop_loop(loop)
        self.assertEqual(report["appliedVersion"], version_of(ips))
        self.assertEqual(report["excludedIps"], [{"ip": "172.20.0.1", "reason": "GATEWAY"}])

    def test_reports_applied_version_and_excluded_ips_every_cycle(self):
        ips = ["203.0.113.10", "172.20.0.1", "2001:DB8::9", "127.0.0.9", "0.0.0.0", "999.1.1.1"]
        self.serve(ips)
        loop = self.start_loop(SET_REAL_IP_FROM="172.20.0.1", WAF_SYNC_EXCLUDE_IPS="10.9.9.9,2001:db8::9")
        self.assertTrue(self.wait_for(lambda: len(FakeBackend.reports) >= 2))
        self.stop_loop(loop)
        expected = {
            "wafId": "local-waf-1",
            "attemptedVersion": version_of(ips),
            "appliedVersion": version_of(ips),
            "lastSyncResult": "SUCCESS",
            # 백엔드가 준 문자열 그대로, 여러 사유면 고정 주소 > 신뢰 프록시 > 게이트웨이 > 설정 순.
            "excludedIps": [
                {"ip": "172.20.0.1", "reason": "TRUSTED_PROXY"},
                {"ip": "2001:DB8::9", "reason": "CONFIGURED_EXCLUSION"},
                {"ip": "127.0.0.9", "reason": "LOOPBACK"},
                {"ip": "0.0.0.0", "reason": "UNSPECIFIED_ADDRESS"},
                {"ip": "999.1.1.1", "reason": "INVALID_FORMAT"},
            ],
            "error": None,
        }
        # 목록이 바뀌지 않아도 주기마다 같은 상태를 다시 보고한다.
        self.assertEqual([r["body"] for r in FakeBackend.reports[:2]], [expected, expected])
        first = FakeBackend.reports[0]
        self.assertEqual(first["path"], "/internal/waf/sync-status")
        self.assertEqual(first["token"], TOKEN)
        self.assertEqual(first["content_type"], "application/json")
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])

    def test_reports_previous_version_when_new_list_fails(self):
        # 기존 목록 A를 쓰다가 B 적용에 실패하면, A가 유지된 것을 확인했으므로 appliedVersion = A다.
        self.serve(["203.0.113.10", "172.20.0.1"])
        self.run_sync()
        version_a = version_of(["203.0.113.10", "172.20.0.1"])
        self.serve(["198.51.100.7"])
        loop = self.start_loop(TEST_NGINX_T_FAIL="1")
        report = self.wait_for_report(lambda r: True)
        self.stop_loop(loop)
        self.assertEqual(report["error"]["code"], "NGINX_TEST_FAILED")
        self.assertTrue(report["error"]["message"].startswith("nginx -t 실패"), report)
        del report["error"]
        self.assertEqual(report, {
            "wafId": "local-waf-1",
            "attemptedVersion": version_of(["198.51.100.7"]),
            "appliedVersion": version_a,
            "lastSyncResult": "FAILURE",
            # 실패한 후보가 아니라 실제 적용 중인 A 기준
            "excludedIps": [{"ip": "172.20.0.1", "reason": "GATEWAY"}],
        })

    def test_reload_timeout_reports_applied_version_only_when_recovered(self):
        version_a, version_b = version_of(["203.0.113.10"]), version_of(["198.51.100.7"])
        cases = {
            # 이전 룰 reload까지 확인 -> A 복구 확인
            "A 복구 확인": ("1", version_a, []),
            # 이전 룰 reload도 확인 못 함 -> 실제 적용 상태 모름
            "적용 상태 모름": ("2", None, None),
        }
        for name, (stalled_reloads, applied, excluded) in cases.items():
            with self.subTest(name):
                FakeBackend.reports = []
                self.serve(["203.0.113.10"])
                self.run_sync()
                self.calls.unlink()
                self.serve(["198.51.100.7"])
                loop = self.start_loop(TEST_NGINX_RELOAD_STALL=stalled_reloads, WAF_RELOAD_TIMEOUT="1")
                failure = self.wait_for_report(lambda r: r["lastSyncResult"] == "FAILURE")
                # 다음 주기에 다시 적용해 B를 확인하면 SUCCESS로 바뀐다.
                self.wait_for_report(lambda r: r["lastSyncResult"] == "SUCCESS" and r["appliedVersion"] == version_b)
                self.stop_loop(loop)
                self.assertEqual(failure["attemptedVersion"], version_b)
                self.assertEqual(failure["appliedVersion"], applied)
                self.assertEqual(failure["excludedIps"], excluded)
                self.assertEqual(failure["error"]["code"], "RELOAD_TIMEOUT")

    def test_reports_fetch_and_format_failures(self):
        self.serve(["203.0.113.10"])
        self.run_sync()
        version_a = version_of(["203.0.113.10"])
        self.serve(status=500, body="{}")
        loop = self.start_loop()
        fetch_failure = self.wait_for_report(lambda r: r["lastSyncResult"] == "FAILURE")
        self.serve(body='{"version":"%s","ipAddresses":[],}' % ("a" * 64))
        format_failure = self.wait_for_report(lambda r: (r["error"] or {}).get("code") == "SNAPSHOT_INVALID")
        self.stop_loop(loop)
        self.assertEqual(fetch_failure, {
            "wafId": "local-waf-1",
            "attemptedVersion": None,   # 대상 version을 모름
            "appliedVersion": version_a,  # nginx는 건드리지 않았으므로 A 유지
            "lastSyncResult": "FAILURE",
            "excludedIps": [],
            "error": {"code": "SNAPSHOT_FETCH_FAILED", "message": "목록 조회 실패: HTTP 500"},
        })
        # 깨진 JSON의 version은 믿을 수 없으므로 시도 version도 null이다.
        self.assertIsNone(format_failure["attemptedVersion"])
        self.assertEqual(format_failure["appliedVersion"], version_a)
        self.assertEqual(self.blocked_ips(), ["203.0.113.10"])

    def test_reports_unknown_when_nginx_is_not_running(self):
        self.serve(["203.0.113.10"])
        loop = self.start_loop()
        self.wait_for_report(lambda r: r["lastSyncResult"] == "SUCCESS")
        self.pid_file.unlink()
        unknown = self.wait_for_report(lambda r: r["lastSyncResult"] == "UNKNOWN")
        self.stop_loop(loop)
        self.assertEqual(unknown, {
            "wafId": "local-waf-1",
            "attemptedVersion": version_of(["203.0.113.10"]),
            "appliedVersion": None,
            "lastSyncResult": "UNKNOWN",
            "excludedIps": None,
            "error": None,
        })

    def test_report_failure_keeps_rules_and_recovers(self):
        FakeBackend.report_status = 404   # 백엔드 보고 API가 아직 없음
        self.serve(["203.0.113.10"])
        loop = self.start_loop()
        self.assertTrue(self.wait_for(lambda: len(FakeBackend.reports) >= 3))
        FakeBackend.report_status = 204
        reported = len(FakeBackend.reports)
        self.assertTrue(self.wait_for(lambda: len(FakeBackend.reports) >= reported + 1))
        output = self.stop_loop(loop)
        # 보고 실패는 차단 설정을 되돌리지 않고, 같은 실패는 한 번만 기록한다.
        self.assertEqual(self.blocked_ips(), ["203.0.113.10"])
        self.assertEqual(self.nginx_calls(), ["-t", "-s reload"])
        self.assertEqual(output.count("상태 보고 실패"), 1, output)
        self.assertIn("HTTP 404", output)
        self.assertIn("상태 보고 복구", output)
        # 실패한 보고를 쌓아 두지 않고 주기마다 최신 상태 하나만 보낸다(조회 수보다 많을 수 없다).
        self.assertLessEqual(len(FakeBackend.reports), len(FakeBackend.tokens))

    def test_report_connection_failure_and_timeout_do_not_block_sync(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        self.serve(["203.0.113.10"])
        loop = self.start_loop(WAF_SYNC_STATUS_URL=f"http://127.0.0.1:{closed_port}/internal/waf/sync-status")
        self.assertTrue(self.wait_for(lambda: len(FakeBackend.tokens) >= 2))
        output = self.stop_loop(loop)
        self.assertIn("상태 보고 실패, 차단 설정은 그대로 두고 다음 주기에 최신 상태를 보고한다: 연결 실패", output)
        self.assertEqual(self.blocked_ips(), ["203.0.113.10"])

        # 백엔드가 응답하지 않아도 5초 뒤 포기하고 다음 동기화를 계속한다.
        FakeBackend.report_hold = threading.Event()
        self.addCleanup(FakeBackend.report_hold.set)
        FakeBackend.tokens = []
        loop = self.start_loop()
        self.assertTrue(self.wait_for(lambda: len(FakeBackend.tokens) >= 2, timeout=12), "보고 대기 때문에 동기화가 멈췄다")
        output = self.stop_loop(loop)
        self.assertIn("응답 시간 초과", output)

    def test_invalid_waf_id_disables_report_but_not_sync(self):
        self.serve(["203.0.113.10"])
        loop = self.start_loop(WAF_ID="WAF 1")
        self.assertTrue(self.wait_for(lambda: len(FakeBackend.tokens) >= 2))
        output = self.stop_loop(loop)
        self.assertIn("상태를 보고하지 않는다", output)
        self.assertEqual(FakeBackend.reports, [])
        self.assertEqual(self.blocked_ips(), ["203.0.113.10"])

    def test_missing_token_does_not_touch_rules(self):
        self.serve(["203.0.113.10"])
        result = self.run_sync(WAF_SYNC_TOKEN="")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.rules.exists())
        self.assertEqual(FakeBackend.tokens, [])


if __name__ == "__main__":
    unittest.main()
