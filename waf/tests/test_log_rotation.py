"""임시 폴더에서 교체 스크립트의 원본 보존을 검증한다. Docker는 호출하지 않는다."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "rotate-logs.sh"


class LogRotationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="waf-rotation-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        (self.root / "nginx.pid").write_text(str(os.getpid()))
        self.lock = self.root / "rotation.lock"
        # 실제 스크립트 본문을 실행하되 컨테이너 경로와 nginx만 테스트용으로 바꾼다.
        self.body = SCRIPT.read_text().split("<<'SH'\n", 1)[1].rsplit("\nSH", 1)[0]
        self.body = self.body.replace("log_dir=/var/log/nginx", f"log_dir={self.logs}")
        self.body = self.body.replace("pid_file=/tmp/nginx.pid", f"pid_file={self.root}/nginx.pid")
        self.body = self.body.replace("lock=/tmp/waf-log-rotation.lock", f"lock={self.lock}")
        nginx = self.root / "nginx"
        nginx.write_text(
            '#!/bin/sh\n'
            'test "$*" = "-s reopen" || exit 2\n'
            'test "${TEST_REOPEN_FAIL:-0}" = 0 || exit 1\n'
            'touch "$TEST_LOG_DIR/access.log" "$TEST_LOG_DIR/error.log"\n'
        )
        nginx.chmod(0o700)
        self.env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}",
                        TEST_LOG_DIR=str(self.logs))

    def run_rotation(self, mode="rotate"):
        return subprocess.run(["sh", "-s", "--", mode], input=self.body,
                              text=True, capture_output=True, env=self.env, timeout=15)

    def test_dry_run_preserves_files_and_creates_no_archive(self):
        source = self.logs / "access.log"
        source.write_bytes(b"request-one\n")
        before = source.stat().st_ino
        result = self.run_rotation("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(source.read_bytes(), b"request-one\n")
        self.assertEqual(source.stat().st_ino, before)
        self.assertFalse((self.logs / "archive").exists())

    def test_rotation_preserves_bytes_and_inode_without_touching_audit(self):
        originals = {}
        for name in ("access.log", "error.log", "modsec_audit.log"):
            source = self.logs / name
            source.write_bytes((name + "\n").encode())
            originals[name] = (source.read_bytes(), source.stat().st_ino)
        result = self.run_rotation()
        self.assertEqual(result.returncode, 0, result.stderr)
        archive, = (self.logs / "archive").iterdir()
        for name in ("access.log", "error.log"):
            self.assertEqual((archive / name).read_bytes(), originals[name][0])
            self.assertEqual((archive / name).stat().st_ino, originals[name][1])
            self.assertEqual((self.logs / name).read_bytes(), b"")
        self.assertEqual((self.logs / "modsec_audit.log").read_bytes(), originals["modsec_audit.log"][0])
        self.assertFalse(self.lock.exists())

    def test_empty_and_missing_files_are_not_archived(self):
        (self.logs / "access.log").touch()
        result = self.run_rotation()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.logs / "archive").exists())

    def test_existing_lock_prevents_moves(self):
        self.lock.mkdir()
        (self.logs / "access.log").write_text("keep\n")
        self.assertNotEqual(self.run_rotation().returncode, 0)
        self.assertEqual((self.logs / "access.log").read_text(), "keep\n")

    def test_symlink_rejected_before_any_move(self):
        (self.logs / "access.log").write_text("keep\n")
        (self.logs / "error.log").symlink_to(self.root / "missing")
        self.assertNotEqual(self.run_rotation().returncode, 0)
        self.assertEqual((self.logs / "access.log").read_text(), "keep\n")
        self.assertFalse((self.logs / "archive").exists())

    def test_reopen_failure_keeps_archived_content(self):
        (self.logs / "access.log").write_text("recover-me\n")
        self.env["TEST_REOPEN_FAIL"] = "1"
        self.assertNotEqual(self.run_rotation().returncode, 0)
        archive, = (self.logs / "archive").iterdir()
        self.assertEqual((archive / "access.log").read_text(), "recover-me\n")
        self.assertFalse(self.lock.exists())


if __name__ == "__main__":
    unittest.main()
