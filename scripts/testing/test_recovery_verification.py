"""복구 검증 실행기의 준비 중단·대상 제한 검사. 외부 명령은 실행하지 않는다."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_recovery_verification as runner


class RecoveryRunnerTests(unittest.TestCase):
    def test_rejects_nonisolated_database_name(self):
        with patch.object(runner, "run") as command:
            with self.assertRaises(ValueError):
                runner.mysql("SELECT 1", "unrelated_db")
            command.assert_not_called()

    def test_low_memory_stops_before_external_commands(self):
        parent = Path(__file__).resolve().parents[2] / "build/test-unit-temp"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root = Path(directory)
            self.assertTrue(root.resolve().is_relative_to(parent.resolve()))
            with patch.object(runner, "ROOT", root), \
                    patch.object(runner, "memory", return_value=512 * 1024**2), \
                    patch.object(runner, "run") as command, \
                    patch("sys.argv", ["runner", "--execute"]), patch("builtins.print"):
                self.assertEqual(runner.main(), 1)
                command.assert_not_called()
            result = json.loads(next((root / "build/test-runs").glob("*/result.json")).read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "INCONCLUSIVE")
            report = next((root / "docs/testing/local/runs").glob("*.md")).read_text(encoding="utf-8")
            self.assertIn("상태: FINISHED / 판정: INCONCLUSIVE", report)

    def test_snapshot_keeps_only_required_container_metadata(self):
        containers = json.dumps({"Service": "db", "ID": "test", "Image": "mysql:test", "State": "running",
                                 "Health": "healthy", "Status": "Up", "Labels": "unneeded"})
        with patch.object(runner, "run", return_value=containers), \
                patch.object(runner, "mysql", return_value="network_logs\t5\n"):
            result = runner.live_snapshot()
        self.assertNotIn("Labels", result["containers"][0])
        self.assertEqual(result["containers"][0]["Service"], "db")


if __name__ == "__main__":
    unittest.main()
