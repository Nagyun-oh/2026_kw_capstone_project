import asyncio
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from run_e2e import main
from summarize_e2e import summarize


class RuntimeTests(unittest.TestCase):
    def test_browser_dependency_failure_preserves_planned_report_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, report = root/'raw-run', root/'report.md'
            (output/'raw').mkdir(parents=True)
            with patch('run_e2e.reserve', return_value=(output, report)), \
                 patch('run_e2e.Experiment.execute', return_value=None), \
                 patch('run_e2e.asyncio.run', side_effect=ImportError('browser')), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--execute', '--confirm-ip-policy']), 1)
            manifest = json.loads((output/'manifest.json').read_text(encoding='utf-8'))
            metrics = json.loads((output/'metrics.json').read_text(encoding='utf-8'))
            self.assertEqual(manifest['state'], 'BLOCKED')
            self.assertEqual(metrics['verdict'], 'INCONCLUSIVE')
            self.assertTrue(report.exists())
            self.assertTrue((output/'measurement-contract.json').exists())
            self.assertTrue(metrics['evidence_sha256'])

    def runs(self, root, verdicts=('PASS', 'PASS', 'PASS')):
        paths = []
        for i, verdict in enumerate(verdicts):
            path = root/str(i)
            path.mkdir()
            manifest = dict(id=str(i), schema='local-e2e-v2', rate=1, seconds=120,
                            connection_check=False, warmup_seconds=30, images=['container image digest'],
                            state='COMPLETED', fixture_sha256='fixture', contract_sha256='contract',
                            runner_files_sha256={}, app_sources_sha256={}, versions={}, ip_policy_confirmed=True)
            (path/'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            (path/'metrics.json').write_text(json.dumps(dict(verdict=verdict,
                latency_samples_ms={'AI_receive': [i+1, 10*(i+1)]})), encoding='utf-8')
            paths.append(path)
        return paths

    def test_step_requires_all_three_pass_and_pools_raw_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            result = summarize(self.runs(Path(directory)))
            self.assertEqual(result['verdict'], 'PASS')
            self.assertEqual(result['pooled_stats_ms']['AI_receive']['count'], 6)
            self.assertEqual(result['pooled_stats_ms']['AI_receive']['p50_ms'], 6.5)

    def test_failed_or_unknown_round_is_not_hidden_by_majority(self):
        for verdict, expected in [('FAIL', 'FAIL'), ('INCONCLUSIVE', 'INCONCLUSIVE')]:
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory() as directory:
                self.assertEqual(summarize(self.runs(Path(directory), ('PASS', verdict, 'PASS')))['verdict'], expected)

    def test_incompatible_or_repeated_runs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.runs(Path(directory))
            with self.assertRaises(ValueError):
                summarize([paths[0]]*3)
            path = paths[1]/'manifest.json'
            value = json.loads(path.read_text(encoding='utf-8'))
            value['rate'] = 3
            path.write_text(json.dumps(value), encoding='utf-8')
            with self.assertRaises(ValueError):
                summarize(paths)
