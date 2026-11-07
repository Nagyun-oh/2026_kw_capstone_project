import argparse
import contextlib
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

from e2e_core import fixture
from e2e_environment import E2EEnvironment, result_paths, select_environment
from run_e2e import Experiment, arguments, build_request, main, request, request_opener
from run_experiment import reserve


TARGET = "https://security-juiceshop-kw.duckdns.org/"
DASHBOARD = "https://security-monitor-kw.duckdns.org/"


class EnvironmentTests(unittest.TestCase):
    def test_local_defaults_preserve_ipv4_host_and_old_schema(self):
        env = select_environment()
        probe, _ = fixture()
        req = build_request('measurement', 1, 'test-run', probe, environment=env)
        self.assertEqual(env.schema, 'local-e2e-v2')
        self.assertTrue(env.execution_ready)
        self.assertEqual(env.target_url, 'http://localhost/')
        self.assertEqual(req.full_url, 'http://127.0.0.1/rest/user/login')
        self.assertEqual(req.get_header('Host'), 'localhost')

    def test_ec2_builder_uses_https_domain_without_localhost_host_override(self):
        env = select_environment('ec2')
        probe, _ = fixture()
        with patch('urllib.request.urlopen', side_effect=AssertionError('HTTP')):
            req = build_request('measurement', 1, 'test-run', probe, environment=env)
        self.assertEqual(req.full_url, TARGET + 'rest/user/login')
        self.assertEqual(env.dashboard_url, DASHBOARD)
        self.assertIsNone(req.get_header('Host'))
        self.assertEqual(json.loads(req.data), probe['body'])
        self.assertEqual(req.get_header('X-dualguard-test-run'), 'test-run')

    def test_ec2_background_request_stays_in_target_root(self):
        probe, _ = fixture()
        req = build_request('warmup', 999999, 'test', probe, kind='background', environment=select_environment('ec2'))
        self.assertEqual(req.full_url, TARGET)
        self.assertEqual(req.get_method(), 'GET')
        self.assertIsNone(req.data)

    def test_default_ports_and_missing_trailing_slash_are_canonicalized(self):
        env = select_environment('ec2', TARGET[:-1] + ':443/', DASHBOARD[:-1])
        self.assertEqual(env.target_url, TARGET)
        self.assertEqual(env.dashboard_url, DASHBOARD)
        self.assertEqual(select_environment('local', 'http://localhost:80/').target_url, 'http://localhost/')

    def test_invalid_target_urls_are_rejected_without_disclosing_input(self):
        invalid = [
            'http://security-juiceshop-kw.duckdns.org/',
            'https://localhost/', 'https://127.0.0.1/',
            TARGET.replace('.org/', '.org.evil/'), TARGET.replace('.org/', '.org.:443/'),
            TARGET[:-1] + ':444/', TARGET[:-1] + ':0/', TARGET[:-1] + ':/',
            TARGET + '?private-token=secret', TARGET + '#secret', TARGET + 'other-path',
            ' ' + TARGET, TARGET + '\n', TARGET.replace('https://', 'https://user:private-token@'),
            TARGET.replace('https://', 'https://user@'), TARGET.replace('https://', 'https:\\'),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError) as error:
                select_environment('ec2', target_url=value)
            self.assertNotIn('private-token', str(error.exception))
            self.assertNotIn('secret', str(error.exception))

    def test_environment_urls_cannot_be_swapped(self):
        for name, kwargs in [('local', {'target_url': TARGET}), ('ec2', {'dashboard_url': TARGET}),
                             ('ec2', {'target_url': DASHBOARD}), ('ec2', {'dashboard_url': 'http://localhost:3000/'})]:
            with self.subTest(name=name, kwargs=kwargs), self.assertRaises(ValueError):
                select_environment(name, **kwargs)

    def test_direct_environment_construction_cannot_bypass_allowlist(self):
        with self.assertRaises(ValueError):
            E2EEnvironment('ec2', 'https://other-host/', DASHBOARD)
        with self.assertRaises(ValueError):
            E2EEnvironment('unknown', TARGET, DASHBOARD)

    def test_request_path_cannot_escape_origin_or_contain_control_characters(self):
        env = select_environment('ec2')
        for path in ('//other-host/', 'https://other-host/', '/\\other-host/', '/\r\nHost: other-host', ''):
            with self.subTest(path=path), self.assertRaises(ValueError):
                env.probe_url(path)

    def test_tls_verifies_certificate_and_hostname_and_redirects_are_disabled(self):
        opener = request_opener(select_environment('ec2'))
        handler = next(h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler))
        self.assertEqual(handler._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(handler._context.check_hostname)
        redirect = next(h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
        self.assertIsNone(redirect.redirect_request(None, None, 302, 'Found', {}, 'https://other-host/'))

    def test_ec2_execute_is_blocked_before_reservation_commands_or_http(self):
        for extra in ([], ['--connection-check']):
            with self.subTest(extra=extra), patch('run_e2e.reserve') as reserved, \
                    patch('run_e2e.command') as command, patch('run_e2e.request') as http, \
                    patch('run_e2e.asyncio.run') as runner, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(['--environment', 'ec2', '--execute', '--confirm-ip-policy', *extra])
                reserved.assert_not_called()
                command.assert_not_called()
                http.assert_not_called()
                runner.assert_not_called()

    def test_direct_ec2_request_and_experiment_are_also_blocked(self):
        env = select_environment('ec2')
        probe, _ = fixture()
        with patch('run_e2e.urllib.request.build_opener') as opener:
            with self.assertRaises(ValueError):
                request('measurement', 1, 'test', probe, environment=env)
        opener.assert_not_called()
        with self.assertRaises(ValueError):
            Experiment(argparse.Namespace(runtime_environment=env), {}, probe, {}, Path('unused'), Path('unused.md'))

    def test_dry_run_has_ec2_plan_without_local_slo_or_any_execution(self):
        output = io.StringIO()
        with patch('run_e2e.reserve', side_effect=AssertionError('write')), \
                patch('run_e2e.command', side_effect=AssertionError('command')), \
                patch('run_e2e.asyncio.run', side_effect=AssertionError('execute')), \
                patch('run_e2e.urllib.request.build_opener', side_effect=AssertionError('HTTP')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(main(['--environment', 'ec2', '--dry-run', '--rate', '3']), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value['environment'], 'ec2')
        self.assertEqual(value['schema'], 'ec2-e2e-v1')
        self.assertIn('-ec2-e2e-rps3-', value['id'])
        self.assertEqual(value['target_url'], TARGET)
        self.assertEqual(value['dashboard_url'], DASHBOARD)
        self.assertTrue(value['tls_verification'])
        self.assertFalse(value['execution_ready'])
        self.assertEqual(value['targets_status'], 'confirmed_ec2_contract_dedicated_runner')
        self.assertIn('docs/testing/ec2/runs/', value['planned_report'])
        self.assertNotIn('docs/testing/local', value['planned_report'])

    def test_local_dry_run_still_uses_existing_contract(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['--dry-run']), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value['schema'], 'local-e2e-v2')
        self.assertEqual(value['environment'], 'local')
        self.assertTrue(value['execution_ready'])
        self.assertEqual(value['targets_status'], 'local_existing_contract')
        self.assertIn('docs/testing/local/runs/', value['planned_report'])

    def test_result_paths_are_separate_without_creating_files(self):
        local = result_paths(Path('unused-root'), 'run-id', 'local')
        ec2 = result_paths(Path('unused-root'), 'run-id', 'ec2')
        self.assertEqual(local[0], ec2[0])
        self.assertNotEqual(local[1], ec2[1])
        self.assertEqual(ec2[1], Path('unused-root/docs/testing/ec2/runs/run-id.md'))

    def test_bad_paths_are_rejected_before_file_creation(self):
        for env, run_id in [('other', 'run'), ('../ec2', 'run'), ('ec2', '../run'),
                            ('ec2', 'path\\run'), ('ec2', '..'), ('local', '')]:
            with self.subTest(env=env, run_id=run_id), patch.object(Path, 'mkdir') as mkdir:
                with self.assertRaises(ValueError):
                    reserve(Path('unused-root'), run_id, env)
                mkdir.assert_not_called()

    def test_ec2_reservation_does_not_write_to_local_reports_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, report = reserve(root, 'ec2-test', 'ec2')
            self.assertTrue((output/'raw').is_dir())
            self.assertTrue(report.is_relative_to(root/'docs/testing/ec2/runs'))
            self.assertFalse((root/'docs/testing/local').exists())
            report.write_text('preserved', encoding='utf-8')
            with self.assertRaises(FileExistsError):
                reserve(root, 'ec2-test', 'ec2')
            self.assertEqual(report.read_text(encoding='utf-8'), 'preserved')


if __name__ == '__main__':
    unittest.main()
