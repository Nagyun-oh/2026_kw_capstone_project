import contextlib
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from recheck_ec2_table import main,matching_group_response,safe_group,target_from_source


class TableRecheckTests(unittest.TestCase):
    def test_group_evidence_discards_descriptions_and_unrelated_fields(self):
        result=safe_group(dict(content=[dict(id=1,logId=2,wafThreatId=1,aiThreatId=3,
            threatTypes=['WAF Detection','AI Detection'],description='private',ipAddress='private')]))
        self.assertEqual(set(result[0]),{'id','logId','wafThreatId','aiThreatId','threatTypes'})
        self.assertNotIn('private',str(result))

    def test_invalid_group_response_is_not_an_empty_success(self):
        for value in ({},dict(content=None),[],None):
            with self.assertRaisesRegex(ValueError,'GROUP_RESPONSE'):
                safe_group(value)

    def test_only_requested_group_search_response_matches(self):
        def response(url,method='GET'):
            return SimpleNamespace(url=url,request=SimpleNamespace(method=method))
        url='https://security-monitor-kw.duckdns.org/api/v1/threats/grouped?threatId=681&page=0'
        self.assertTrue(matching_group_response(response(url),681))
        self.assertFalse(matching_group_response(response(url),682))
        self.assertFalse(matching_group_response(response(url,'POST'),681))
        self.assertFalse(matching_group_response(response(url.replace('threats/grouped','logs')),681))

    def test_source_run_rejects_path_escape_before_file_read(self):
        for value in ('../private','C:/secret','x/ec2-connection-r01','20261105-local-normal-r01'):
            with self.assertRaisesRegex(ValueError,'SOURCE_RUN_ID'):
                target_from_source(value)

    def test_plan_does_not_open_browser_or_reserve_result_files(self):
        with (patch('recheck_ec2_table.target_from_source',return_value={}),
                patch('recheck_ec2_table.reserve') as reserve,
                patch('recheck_ec2_table.observe') as observe,contextlib.redirect_stdout(io.StringIO())):
            self.assertEqual(main(['--source-run','source']),0)
        reserve.assert_not_called()
        observe.assert_not_called()
