"""응답·access 메타데이터와 기존 헤더 마스킹 회귀 검증. Nginx 실기동은 별도다."""
import base64
import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MeasurementMetadataTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'node 필요')
    def test_start_time_uses_nginx_clock_and_existing_masking_is_preserved(self):
        source = (ROOT/'waf/njs/headers.js').read_bytes()
        code = "import m from 'data:text/javascript;base64," + base64.b64encode(source).decode() + "';\n"
        code += """
const r={variables:{msec:'1793515480.432',request_time:'0.025'},
headersIn:{Cookie:'private',Authorization:'private','X-DualGuard-Test-Run':'run'}};
console.log(JSON.stringify({start:m.requestStart(r),headers:JSON.parse(m.dump(r))}));
"""
        result = subprocess.run(['node', '--input-type=module', '-e', code], capture_output=True,
                                text=True, encoding='utf-8', timeout=10, check=True)
        data = json.loads(result.stdout)
        self.assertEqual(data['start'], '1793515480.407')
        self.assertEqual(data['headers']['Cookie'], '***MASKED***')
        self.assertEqual(data['headers']['Authorization'], '***MASKED***')
        self.assertEqual(data['headers']['X-DualGuard-Test-Run'], 'run')

    def test_config_uses_server_id_and_json_escaping(self):
        body = (ROOT/'waf/nginx-logging.conf.template').read_text(encoding='utf-8')
        self.assertIn('escape=json', body)
        self.assertIn("more_set_headers 'X-Request-ID: $request_id'", body)
        self.assertNotIn('X-Request-ID: $http_', body)
        for field in ('request_start_epoch_s', 'test_run', 'test_phase', 'test_kind', 'test_seq'):
            self.assertIn('"' + field + '"', body)
        self.assertIn('js_set $dg_request_start_epoch_s log_headers.requestStart',
                      (ROOT/'waf/nginx.conf.template').read_text(encoding='utf-8'))
