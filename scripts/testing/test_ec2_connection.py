import copy
import json
from pathlib import Path
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import Mock, patch

from ec2_connection import (RequestBudget, connection_checks, owned_blacklist,
    public_state, with_generator, observe_threat_row)
from e2e_core import fixture
from e2e_environment import select_environment
from run_ec2_connection import ConnectionRun, main


class ConnectionTests(TestCase):
    def test_preserves_existing_exclusions_and_is_idempotent(self):
        original = '172.18.0.1, 192.168.1.2'
        value = with_generator(original,'8.8.8.8')
        self.assertEqual(value,original+',8.8.8.8')
        self.assertEqual(with_generator(value,'8.8.8.8'),value)

    def test_rejects_cidr_invalid_original_and_private_source(self):
        for original, source in [('172.18.0.0/16','8.8.8.8'),('a;cmd','8.8.8.8'),('','127.0.0.1')]:
            with self.assertRaises(ValueError): with_generator(original,source)

    def test_existing_blacklist_is_never_cleanup_target(self):
        old = dict(id=1,requestId='old',runId='old')
        new = dict(id=2,requestId='probe',runId='run')
        self.assertEqual(owned_blacklist([old],[old,new],'run','probe'),[2])
        self.assertEqual(owned_blacklist([old],[old],'run',None),[])

    def test_unrelated_blacklist_aborts_cleanup(self):
        for row in [dict(id=2,requestId='other',runId='run'),dict(id=2,requestId='probe',runId=None)]:
            with self.assertRaisesRegex(ValueError,'OWNERSHIP'):
                owned_blacklist([], [row], 'run','probe')

    def test_public_artifact_has_alias_booleans_and_no_generator_ip(self):
        value = dict(status='OK',private=dict(source_ipv4='8.8.8.8',exclusions='8.8.8.8,172.18.0.1',blacklist=[]))
        result = public_state(value)
        self.assertTrue(result['generator_excluded'])
        self.assertNotIn('8.8.8.8',json.dumps(result))
        self.assertNotIn('172.18.0.1',json.dumps(result))

    def test_probe_budget_blocks_second_probe_before_http(self):
        budget = RequestBudget()
        budget.probes = 1
        with patch('ec2_connection.request_opener') as opener:
            with self.assertRaisesRegex(ValueError,'BUDGET'):
                budget.send('r-ec2-connection-r01',fixture()[0],1,{},probe=True)
        opener.assert_not_called()

    def test_total_budget_and_run_id_block_before_http(self):
        budget = RequestBudget()
        budget.used = 5
        with self.assertRaisesRegex(ValueError,'BUDGET'):
            budget.send('r-ec2-connection-r01',fixture()[0],1,{})
        with self.assertRaisesRegex(ValueError,'RUN_ID'):
            RequestBudget().send('local-normal',fixture()[0],1,{})

    def test_ec2_full_load_is_still_blocked(self):
        with self.assertRaises(ValueError): select_environment('ec2').require_execution_ready()

    def test_dry_run_has_no_http_ssh_or_files(self):
        with patch('run_ec2_connection.reserve') as reserve, patch('run_ec2_connection.ConnectionRun') as run:
            self.assertEqual(main(['--dry-run']),0)
        reserve.assert_not_called()
        run.assert_not_called()

    def test_empty_evidence_cannot_pass(self):
        result = connection_checks([],[],[],[])
        self.assertFalse(result['request_count'])
        self.assertFalse(result['database_once'])
        self.assertFalse(result['probe_two_sources'])

    def complete(self):
        clients = [dict(phase='measurement',kind='probe' if i==3 else 'background',requestId=str(i)*32,status=200) for i in range(4)]
        db = [dict(requestId=c['requestId'],aiRows=1 if i==3 else 0,wafRows=1 if i==3 else 0,
            alertId='a',revision=2) for i,c in enumerate(clients)]
        traces = [dict(stage=s,requestId=c['requestId']) for c in clients for s in ('LOG_COMMITTED','AI_RESULT_COMMITTED')]
        traces += [dict(stage='ALERT_SEND_RETURNED',requestId=clients[3]['requestId'],alertId='a',revision=2,sources=['WAF','AI'])]
        browser = [dict(kind=k,alertId='a',sources=['WAF','AI'],duplicateCount=1) for k in ('received','dom')]
        return clients,db,traces,browser

    def test_full_connection_requires_log_ai_waf_send_receive_dom(self):
        values = self.complete()
        self.assertTrue(all(connection_checks(*values).values()))
        for index in (1,2,3):
            broken = copy.deepcopy(values)
            broken[index].clear()
            self.assertFalse(all(connection_checks(*broken).values()))

    def test_duplicate_db_row_and_two_popups_fail(self):
        values = self.complete()
        values[1].append(values[1][0])
        self.assertFalse(connection_checks(*values)['database_once'])
        values = self.complete()
        values[3][1]['duplicateCount']=2
        self.assertFalse(connection_checks(*values)['single_popup'])


class CleanupTests(IsolatedAsyncioTestCase):
    def runner(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        directory = Path(self.temp.name)
        return ConnectionRun(Mock(),directory,directory/'report.md',dict(id='test-ec2-connection-r01'))

    async def test_cleanup_does_not_delete_unrelated_entry(self):
        run = self.runner()
        run.baseline = dict(blacklist=[])
        run.probe_id = 'probe'
        from unittest.mock import AsyncMock
        run.inspect = AsyncMock(return_value=dict(blacklist=[dict(id=1,runId='other',requestId='probe')]))
        run.page = Mock(evaluate=AsyncMock())
        with self.assertRaisesRegex(ValueError,'OWNERSHIP'):
            await run.cleanup()
        run.page.evaluate.assert_not_called()

    async def test_cleanup_uses_api_then_confirms_baseline(self):
        from unittest.mock import AsyncMock
        run = self.runner()
        run.baseline = dict(blacklist=[])
        run.probe_id='probe'
        run.inspect = AsyncMock(side_effect=[dict(blacklist=[dict(id=2,runId='test-ec2-connection-r01',requestId='probe')]),dict(blacklist=[])])
        run.page = Mock(evaluate=AsyncMock(return_value=204))
        await run.cleanup()
        self.assertTrue(run.cleanup_ok)
        self.assertEqual(run.page.evaluate.call_args.args[1],2)

    async def test_noop_reconfigure_keeps_observation_enabled(self):
        from unittest.mock import AsyncMock
        run=self.runner()
        run.inspect=AsyncMock(return_value=dict(exclusions=''))
        await run.reconfigure('','same')
        self.assertFalse(run.pause_monitor)


class BrowserDOMTests(IsolatedAsyncioTestCase):
    async def test_duplicate_log_buttons_are_scoped_to_threat_table(self):
        from playwright.async_api import async_playwright, Error
        async with async_playwright() as pw:
            browser=await pw.chromium.launch(channel='chrome',headless=True)
            try:
                page=await browser.new_page()
                await page.set_content('''
                  <section aria-label="위협 탐지 목록">
                    <form onsubmit="event.preventDefault()">
                      <input name="threatId"><button>검색</button>
                    </form>
                    <div role="region" aria-label="위협 탐지 데이터 표">
                      <button aria-label="원본 로그 42 상세 보기">로그 #42</button>
                    </div>
                  </section>
                  <section><button aria-label="원본 로그 42 상세 보기">#42</button></section>
                ''')
                # 기존 전역 검색은 두 표의 버튼을 동시에 찾아 strict mode에서 실패한다.
                with self.assertRaises(Error):
                    await page.get_by_role('button',name='원본 로그 42 상세 보기',exact=True).wait_for(state='visible')
                await observe_threat_row(page,10,42)
                self.assertEqual(await page.locator('input[name="threatId"]').input_value(),'10')
            finally:
                await browser.close()
