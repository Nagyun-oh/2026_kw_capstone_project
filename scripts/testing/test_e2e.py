import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from e2e_core import (SPEC, fixture, client_record, parse_traces, parse_points,
                      browser_record, database_sql, evaluate, parse_database)
from run_e2e import arguments, main, report, request

RID = 'A' * 32
BID = 'b' * 32
AID = '1269a7b5-5db9-4f4b-a5ce-a4f09a56cabb'
T0 = 1793515480.0


def at(delta):
    return datetime.fromtimestamp(T0 + delta, timezone.utc).isoformat()


def example():
    clients = [dict(requestId=rid, phase='measurement', kind=kind, sequence=0,
                    ingress=T0, status=200, duration_ms=5, c0=100)
               for rid, kind in [(RID, 'probe'), (BID, 'background')]]
    traces = []
    for rid in (RID, BID):
        for stage, delta in [('LOG_COMMITTED', .1), ('AI_RESULT_COMMITTED', .2)]:
            traces.append(dict(requestId=rid, stage=stage, outcome='DETECTED' if rid == RID else 'NORMAL',
                               at=at(delta), threatId=11 if rid == RID else None, alertId=None))
    traces += [dict(requestId=RID, stage='WAF_COMMITTED', outcome='CREATED', at=at(.15),
                    threatId=10, alertId=None),
               dict(requestId=RID, stage='ALERT_SEND_RETURNED', at=at(.3), outcome=None,
                    alertId=AID, revision=2, sources=['WAF', 'AI'])]
    db = [dict(requestId=rid, logId=i, phase='measurement', kind=kind, aiRows=1 if rid == RID else 0,
               wafRows=1 if rid == RID else 0, aiDetected=rid == RID, wafDetected=rid == RID,
               alertId=AID if rid == RID else None, revision=2, sequence='0', ingress=str(T0))
          for i, (rid, kind) in enumerate([(RID, 'probe'), (BID, 'background')], 1)]
    browser = [dict(kind=kind, alertId=AID, revision=2, sources=['WAF', 'AI'], observed=observed)
               for kind, observed in [('received', 100.4), ('dom', 100.6)]]
    return clients, traces, db, browser


class E2ETests(unittest.TestCase):
    def test_probe_uses_ipv4_transport_and_preserves_http_host(self):
        probe, _ = fixture()
        with patch('run_e2e.urllib.request.build_opener') as build, \
             patch('run_e2e.client_record', return_value={}):
            response = build.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b''
            response.headers = {}
            response.code = 200
            request('warmup', 1, 'test-run', probe)
        sent = build.return_value.open.call_args.args[0]
        self.assertEqual(sent.full_url, 'http://127.0.0.1/rest/user/login')
        self.assertEqual(sent.get_header('Host'), 'localhost')
        self.assertEqual(json.loads(sent.data), probe['body'])

    def decision(self, dataset=None, **kwargs):
        return evaluate(*(dataset or example()), json.loads(SPEC.read_text(encoding='utf-8')),
                        elapsed=120, final_lag=True, observation_complete=True, **kwargs)

    def test_coalesced_first_message_satisfies_both_sources(self):
        result = self.decision()
        self.assertEqual(result['verdict'], 'PASS')
        self.assertAlmostEqual(result['stats_ms']['AI_receive']['p50_ms'], 400)
        self.assertAlmostEqual(result['stats_ms']['WAF_dom']['p95_ms'], 600)
        self.assertEqual(result['links'][0]['alertId'], AID)

    def test_later_revision_adds_source_without_overwriting_first(self):
        c, t, d, _ = example()
        b = [dict(kind=k, alertId=AID, revision=rev, sources=sources, observed=observed)
             for k, rev, sources, observed in [('received', 1, ['WAF'], 100.4),
                ('received', 2, ['AI', 'WAF'], 100.8), ('dom', 2, ['AI', 'WAF'], 101)]]
        result = self.decision((c, t, d, b))
        self.assertAlmostEqual(result['stats_ms']['WAF_receive']['p50_ms'], 400)
        self.assertAlmostEqual(result['stats_ms']['AI_receive']['p50_ms'], 800)

    def test_latest_revision_must_arrive_even_if_sources_already_seen(self):
        c, t, d, b = example()
        d[0]['revision'] = 3
        self.assertEqual(self.decision((c, t, d, b))['verdict'], 'FAIL')

    def test_background_detection_requires_source_receipt_but_not_dom(self):
        c, t, d, b = example()
        d[1].update(aiDetected=True, aiRows=1, alertId='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', revision=1)
        self.assertEqual(self.decision((c, t, d, b))['verdict'], 'FAIL')
        b.append(dict(kind='received', alertId=d[1]['alertId'], revision=1, sources=['AI'], observed=101))
        self.assertEqual(self.decision((c, t, d, b))['verdict'], 'PASS')

    def test_background_normal_does_not_require_an_alert(self):
        self.assertEqual(self.decision()['verdict'], 'PASS')

    def test_missing_produced_browser_delivery_is_failed_not_zero(self):
        c, t, d, b = example()
        result = self.decision((c, t, d, []))
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertIsNone(result['stats_ms']['AI_receive']['p50_ms'])
        self.assertEqual(result['missing']['AI_receive'], 1)

    def test_probe_not_detected_is_inconclusive_not_notification_loss(self):
        c, t, d, b = example()
        t = [v for v in t if v['stage'] not in {'WAF_COMMITTED', 'ALERT_SEND_RETURNED'}]
        for v in t:
            v['outcome'] = 'NORMAL'
        d[0].update(aiDetected=False, wafDetected=False, aiRows=0, wafRows=0, alertId=None)
        self.assertEqual(self.decision((c, t, d, []))['verdict'], 'INCONCLUSIVE')

    def test_late_dom_and_duplicate_popup_fail(self):
        for changes in ({'observed': 108}, {'duplicateCount': 2}):
            with self.subTest(changes=changes):
                c, t, d, b = example()
                b[1].update(changes)
                self.assertEqual(self.decision((c, t, d, b))['verdict'], 'FAIL')

    def test_missing_stage_does_not_invent_timestamps(self):
        c, t, d, b = example()
        t = [v for v in t if v['stage'] != 'LOG_COMMITTED']
        self.assertEqual(self.decision((c, t, d, b))['verdict'], 'INCONCLUSIVE')

    def test_failures_take_precedence_over_missing_evidence(self):
        c, t, d, b = example()
        c[0]['status'] = 403
        self.assertEqual(self.decision((c, [], d, b), errors=['collector failed'])['verdict'], 'FAIL')

    def test_warmup_is_excluded_and_duplicate_result_is_detected(self):
        c, t, d, b = example()
        c += [dict(c[0], phase='warmup', status=403)]
        self.assertEqual(self.decision((c, t, d, b))['verdict'], 'PASS')
        d[0]['aiRows'] = 2
        self.assertEqual(self.decision((c, t, d, b))['verdict'], 'FAIL')

    def test_id_case_is_preserved(self):
        result = client_record('measurement', 'probe', 1,
            {'X-Request-ID': RID, 'X-DualGuard-Request-Start': str(T0)}, 200, 5, T0*1000, T0*1000+5)
        self.assertEqual(result['requestId'], RID)

    def test_response_id_is_checked_against_database_metadata(self):
        c, t, d, b = example()
        d[0]['sequence'] = '99'
        self.assertEqual(self.decision((c, t, d, b))['verdict'], 'FAIL')

    def test_missing_or_spoofed_id_and_clock_mismatch_are_rejected(self):
        for headers in ({}, {'x-request-id': 'client-id'},
                        {'x-request-id': RID, 'x-dualguard-request-start': str(T0 + 3600)},
                        {'x-request-id': RID, 'x-dualguard-request-start': 'NaN'}):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                client_record('measurement', 'probe', 0, headers, 200, 1, T0*1000, T0*1000+5)

    def test_trace_parser_whitelists_fields_and_retains_utc(self):
        value = dict(schema='dualguard-trace-v1', stage='WAF_COMMITTED', requestId=RID,
                     at=at(.2), cookie='secret', ip='private')
        result = parse_traces('backend | DG_TRACE ' + json.dumps(value))[0]
        self.assertNotIn('cookie', result)
        self.assertNotIn('ip', result)
        self.assertEqual(result['at'], at(.2))
        self.assertEqual(parse_traces('ordinary log'), [])
        with self.assertRaises(ValueError):
            parse_traces('DG_TRACE ' + json.dumps(dict(value, at='no timezone')))

    def test_browser_parser_never_saves_tokens_ip_or_body(self):
        result = browser_record(dict(kind='received', alertId=AID, revision=1, sources=['AI'],
                                ip='private', token='secret', body='secret'), 100)
        self.assertFalse({'ip', 'token', 'body'} & result.keys())
        with self.assertRaises(ValueError):
            browser_record(dict(kind='received', alertId=AID, revision=0, sources=['AI']), 100)

    def test_sql_is_read_only_scoped_and_does_not_use_datetime(self):
        sql = database_sql("x' OR 1=1 --")
        self.assertIn('START TRANSACTION READ ONLY', sql)
        self.assertIn('ROLLBACK;', sql)
        self.assertIn('BINARY a.alert_key', sql)
        self.assertNotIn("x' OR 1=1", sql)
        self.assertNotIn('created_at', sql)

    def test_sql_floor_and_joins_allow_index_lookups_without_datetime(self):
        # 2026/11/08 EC2 실행 계획: 전체 raw_log 해석·탐지 테이블 반복 스캔을 기본 키 범위·인덱스 조회로 바꾼다.
        sql = database_sql('run', 36475)
        self.assertIn('WHERE n.id > 36475 AND BINARY JSON_UNQUOTE(', sql)
        self.assertIn("ON a.alert_key=CONCAT('request:',n.request_id) AND BINARY a.alert_key=", sql)
        self.assertIn('WHERE w.request_id=n.request_id AND BINARY w.request_id=BINARY n.request_id', sql)
        self.assertNotIn('created_at', sql)
        self.assertNotIn('n.id >', database_sql('run'))
        for bad in (-1, '1 OR 1=1', 1.5, True):
            with self.assertRaises(ValueError):
                database_sql('run', bad)

    def test_fixture_has_no_credentials_or_cookie_headers(self):
        value, digest = fixture()
        self.assertEqual(value['path'], '/rest/user/login')
        self.assertEqual(len(digest), 64)
        self.assertNotIn('Cookie', value['headers'])

    def test_invalid_database_is_rejected(self):
        for text in ('[]', '{"requestId":"fake"}'):
            with self.assertRaises(ValueError):
                parse_database(text)

    def test_dry_run_never_reserves_runs_or_imports_browser(self):
        with patch('run_e2e.reserve', side_effect=AssertionError('reserve')), \
             patch('run_e2e.command', side_effect=AssertionError('command')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--dry-run']), 0)

    def test_requires_explicit_ip_policy_and_rejects_high_rate(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for args in (['--execute'], ['--dry-run', '--rate', '10'], ['--dry-run', '--round', '0']):
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    arguments(args)

    def test_partial_k6_line_is_buffered_and_final_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'points'
            path.write_text('{"type":', encoding='utf-8')
            self.assertEqual(parse_points(path, partial=True), [])
            with self.assertRaises(json.JSONDecodeError):
                parse_points(path)

    def test_report_separates_server_browser_dom_and_preserves_missing(self):
        manifest = dict(id='test', planned_at=at(0), rate=1, seconds=120,
                        warmup_seconds=30, connection_check=False, state='COMPLETED')
        result = self.decision()
        result['stats_ms']['AI_receive']['p99_ms'] = None
        text = report(manifest, result, Path('evidence'))
        for expected in ('2026/11/01', 'AI_receive', 'WAF_dom', 'p50 ms', '미측정', 'DB DATETIME'):
            self.assertIn(expected, text)


if __name__ == '__main__':
    unittest.main()
