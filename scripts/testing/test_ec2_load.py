import argparse
import asyncio
import contextlib
import copy
from datetime import datetime,timezone
import io
import json
import os
import shutil
import subprocess
from pathlib import Path
import unittest
from unittest.mock import AsyncMock,Mock,patch

from ec2_load_policy import load_contract,selected_contract,validate_contract,assess,summarize_stage
from ec2_login import Credentials,read_credentials,login_ec2
from e2e_core import evaluate
from run_ec2_e2e import main,EC2Experiment
from e2e_core import fixture
from e2e_environment import select_environment
from e2e_remote import SSHSettings
from test_e2e import example,at,RID,T0


class LoadPolicyTests(unittest.TestCase):
    def setUp(self): self.policy,self.digest=load_contract()

    def test_confirmed_contract_and_pilot_are_separate(self):
        self.assertEqual(selected_contract(self.policy,'pilot',1)['workload']['measurement_seconds'],60)
        self.assertEqual(selected_contract(self.policy,'formal',5)['workload']['measurement_seconds'],120)
        with self.assertRaises(ValueError): selected_contract(self.policy,'pilot',3)
        changed=copy.deepcopy(self.policy)
        changed['initial_targets']['ai_server_e2e_p95_ms']=4000
        with self.assertRaises(ValueError): validate_contract(changed)

    def test_contract_revision_3_separates_lag_measurement_interval(self):
        self.assertEqual(self.policy['revision'],3)
        self.assertEqual(self.policy['workload']['lag_measurement_interval_seconds'],60)
        self.assertEqual(self.policy['workload']['lag_confirmation_interval_seconds'],10)
        for value in (None,10):
            changed=copy.deepcopy(self.policy)
            if value is None: del changed['workload']['lag_measurement_interval_seconds']
            else: changed['workload']['lag_measurement_interval_seconds']=value
            with self.assertRaises(ValueError): validate_contract(changed)

    def test_ec2_http_and_browser_latency_are_reference_but_server_slo_applies(self):
        c,t,d,b=example()
        for row in c: row['duration_ms']=900
        for row in b: row['observed']=110
        spec=selected_contract(self.policy,'pilot',1)
        r=evaluate(c,t,d,b,spec,elapsed=60,final_lag=True,observation_complete=True)
        self.assertEqual(r['verdict'],'PASS')
        next(x for x in t if x['stage']=='AI_RESULT_COMMITTED')['at']=at(4)
        r=evaluate(c,t,d,b,spec,elapsed=60,final_lag=True,observation_complete=True)
        self.assertEqual(r['verdict'],'FAIL')

    def test_waf_uses_p95_three_seconds(self):
        c,t,d,b=example()
        next(x for x in t if x['stage']=='WAF_COMMITTED')['at']=at(3.5)
        r=evaluate(c,t,d,b,selected_contract(self.policy,'pilot',1),elapsed=60,final_lag=True,observation_complete=True)
        self.assertIn('waf_server p95 기준 초과',r['reasons'])

    def test_counts_use_completion_not_detection_rows(self):
        r=assess(*example(),selected_contract(self.policy,'pilot',1),rate=1,elapsed=60,final_lag=True,complete=True)
        self.assertEqual(r['rates']['ai_completed_requests'],2)
        self.assertEqual(r['rates']['committed_logs'],2)
        self.assertEqual(r['verdict'],'INCONCLUSIVE')  # 2건은 확정한 60건 부하를 채우지 못했다.

    def test_complete_sixty_request_pilot_passes_with_six_probes(self):
        clients,traces,db,browser=[],[],[],[]
        for i in range(60):
            rid=f'{i+1:032x}'; aid=f'{i+1:08x}-aaaa-bbbb-cccc-123456789012'; probe=i%10==0
            clients.append(dict(requestId=rid,phase='measurement',kind='probe' if probe else 'background',
                sequence=i,ingress=T0+i,status=200,duration_ms=900,c0=100+i))
            traces += [dict(requestId=rid,stage=stage,outcome='DETECTED' if probe else 'NORMAL',at=at(i+delta),alertId=None)
                for stage,delta in [('LOG_COMMITTED',.1),('AI_RESULT_COMMITTED',.2)]]
            db.append(dict(requestId=rid,logId=i+1,phase='measurement',kind='probe' if probe else 'background',
                sequence=str(i),ingress=str(T0+i),aiRows=int(probe),wafRows=int(probe),
                aiDetected=probe,wafDetected=probe,alertId=aid if probe else None,revision=2))
            if probe:
                traces += [dict(requestId=rid,stage='WAF_COMMITTED',at=at(i+.15),alertId=None),
                    dict(requestId=rid,stage='ALERT_SEND_RETURNED',at=at(i+.3),alertId=aid,revision=2,sources=['WAF','AI'])]
                browser += [dict(kind=k,alertId=aid,revision=2,sources=['WAF','AI'],observed=100+i+.4) for k in ('received','dom')]
        result=assess(clients,traces,db,browser,selected_contract(self.policy,'pilot',1),rate=1,elapsed=60.5,final_lag=True,complete=True)
        self.assertEqual(result['verdict'],'PASS',result['reasons'])
        self.assertEqual(result['counts']['probes'],6)
        self.assertEqual(result['rates']['ai_completed_requests'],60)

    def test_final_drain_and_duplicate_commit_are_failures(self):
        c,t,d,b=example()
        spec=selected_contract(self.policy,'pilot',1)
        self.assertEqual(assess(c,t,d,b,spec,rate=1,elapsed=60,final_lag=False,complete=True)['verdict'],'FAIL')
        t.append(copy.deepcopy(t[0]))
        r=assess(c,t,d,b,spec,rate=1,elapsed=60,final_lag=True,complete=True)
        self.assertEqual(r['verdict'],'FAIL')
        self.assertTrue(any('중복 커밋' in x for x in r['reasons']))

    def formal_runs(self):
        m=dict(mode='formal',schema='ec2-e2e-v1',rate=1,seconds=120,warmup_seconds=30,fixture_sha256='f',
            contract_sha256='c',runner_files_sha256={},app_sha='a',images=['i'],target_url='target',dashboard_url='dashboard',
            versions={},state='COMPLETED')
        return [(dict(m,id=str(i)),dict(verdict='PASS',latency_samples_ms=dict(http=[1,2,3]))) for i in range(3)]

    def test_three_formal_runs_must_all_pass(self):
        rows=self.formal_runs()
        self.assertEqual(summarize_stage(rows)['verdict'],'PASS')
        rows[1][1]['verdict']='FAIL'
        self.assertEqual(summarize_stage(rows)['verdict'],'FAIL')
        rows[1][1]['verdict']='INCONCLUSIVE'
        self.assertEqual(summarize_stage(rows)['verdict'],'INCONCLUSIVE')

    def test_pilot_duplicate_ids_or_changed_conditions_cannot_be_pooled(self):
        for field,value in [('mode','pilot'),('app_sha','changed'),('rate',3),('id','0')]:
            rows=self.formal_runs()
            rows[1][0][field]=value
            with self.assertRaises(ValueError): summarize_stage(rows)

    def test_plan_never_prompts_connects_or_reserves(self):
        with (patch('run_ec2_e2e.read_credentials') as secret,patch('run_ec2_e2e.reserve') as reserve,
                patch('run_ec2_e2e.EC2Experiment') as experiment,contextlib.redirect_stdout(io.StringIO())):
            self.assertEqual(main(['--dry-run','--mode','pilot']),0)
        secret.assert_not_called();reserve.assert_not_called();experiment.assert_not_called()


class LoginTests(unittest.IsolatedAsyncioTestCase):
    def page(self,url='https://security-monitor-kw.duckdns.org/'):
        p=Mock(url=url)
        p.locator.return_value.fill=AsyncMock()
        p.get_by_role.return_value.click=AsyncMock()
        p.wait_for_function=AsyncMock()
        p.evaluate=AsyncMock(side_effect=[False,True])
        return p

    async def test_real_login_form_and_no_credentials_in_repr(self):
        p=self.page();credentials=Credentials('fixture-user','fixture-password','db-fixture')
        await login_ec2(p,credentials)
        self.assertEqual(p.locator.return_value.fill.await_count,2)
        self.assertNotIn('fixture',repr(credentials))
        credentials.clear()
        self.assertEqual(credentials.username,'')
        self.assertIsNone(credentials.db_password)

    async def test_external_http_and_wrong_port_refused_before_credentials(self):
        for url in ('http://security-monitor-kw.duckdns.org/','https://example.test/',
                'https://security-monitor-kw.duckdns.org:444/'):
            p=self.page(url)
            with self.assertRaises(RuntimeError): await login_ec2(p,Credentials('user','secret'))
            p.locator.assert_not_called()

    async def test_browser_exception_does_not_disclose_fill_value(self):
        p=self.page()
        p.locator.return_value.fill.side_effect=RuntimeError('secret-value')
        with self.assertRaises(RuntimeError) as error:
            await login_ec2(p,Credentials('user','secret-value'))
        self.assertNotIn('secret-value',str(error.exception))
        self.assertIsNone(error.exception.__cause__)

    async def test_failed_login_does_not_claim_ready(self):
        p=self.page();p.evaluate.side_effect=[False,False]
        with self.assertRaises(RuntimeError): await login_ec2(p,Credentials('user','secret'))


class CredentialInputTests(unittest.TestCase):
    def test_noninteractive_hidden_input_is_rejected(self):
        with patch('ec2_login.sys.stdin.isatty',return_value=False),patch('ec2_login.getpass.getpass') as prompt:
            with self.assertRaises(RuntimeError):read_credentials()
        prompt.assert_not_called()

    def test_one_console_collects_credentials_in_memory_only(self):
        with patch('ec2_login.sys.stdin.isatty',return_value=True),patch('ec2_login.getpass.getpass',side_effect=['user','secret','db-secret']) as prompt:
            credentials=read_credentials()
        self.assertEqual(prompt.call_count,3)
        self.assertEqual(credentials.db_password,'db-secret')
        self.assertNotIn('secret',repr(credentials))


class GeneratorBoundaryTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('k6'),'k6 설치 필요')
    def test_real_k6_module_caps_http_requests_without_network_calls(self):
        script=Path(__file__).parent/'test_e2e_workload.js'
        result=subprocess.run(['k6','run','--no-color',str(script)],
            capture_output=True,text=True,timeout=15,env=dict(os.environ,K6_NO_USAGE_REPORT='true'))
        self.assertEqual(result.returncode,0,result.stderr)


class RuntimeFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_wide_but_consistent_clock_is_diagnostic_not_server_slo_failure(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            contract,digest=load_contract();spec=selected_contract(contract,'pilot',1)
            m=dict(id='test',contract_sha256=digest)
            r=EC2Experiment(argparse.Namespace(runtime_environment=select_environment('ec2')),contract,spec,
                fixture()[0],m,Path(directory),Path(directory)/'r.md',SSHSettings('example.test',Path('key')),Credentials('u','p'))
            r.setup.recalibrate=AsyncMock();r.setup.clock=dict(uncertainty_width_ms=40)
            await r.calibrate('fixture')
            self.assertIsNone(r.guard.abort)
            self.assertFalse(m['clock_diagnostics'][0]['precise_cross_domain_reference'])

    async def flow(self,failed=False):
        import tempfile
        from types import SimpleNamespace
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        output=Path(self.temp.name);(output/'raw').mkdir()
        contract,digest=load_contract();spec=selected_contract(contract,'pilot',1)
        m=dict(id='20261105T000000+0900-ec2-pilot-r99',contract_sha256=digest,seconds=60,warmup_seconds=30)
        args=argparse.Namespace(runtime_environment=select_environment('ec2'),rate=1)
        r=EC2Experiment(args,contract,spec,fixture()[0],m,output,output/'report.md',
            SSHSettings('example.test',Path('key')),Credentials('fixture','secret','db-secret'))
        r.setup.session=Mock()
        current=dict(exclusions='',app_sha='a'*40,source_ipv4='8.8.8.8',blacklist=[],https_source=dict(rows=1,matches=1))
        r.setup.inspect=AsyncMock(side_effect=lambda *a,**k:copy.deepcopy(current))
        r.setup.private_state=Mock()
        async def reconfigure(desired,label):
            r.setup.changed=True;current['exclusions']=desired;r.setup.current=copy.deepcopy(current)
        r.setup.reconfigure=AsyncMock(side_effect=reconfigure)
        r.setup.cleanup=AsyncMock()
        r.setup.recalibrate=AsyncMock();r.setup.clock={}
        r.setup.sync_status=AsyncMock(return_value=dict(status='APPLIED',stale=False))
        r.guard_baseline=AsyncMock();r.calibrate=AsyncMock();r.clock_calibration={}
        r.monitor=AsyncMock();r.sampler=AsyncMock();r.drain=AsyncMock(return_value=True)
        r.table_check=AsyncMock()
        r.database_observation=AsyncMock()
        async def phase(name,seconds,rate):
            if failed: raise RuntimeError('FIXTURE_LOAD_FAILURE')
            return seconds
        r.phase=AsyncMock(side_effect=phase)
        remote=dict(transport={},commands=[],collection_status='COLLECTED',errors=[],app_sha='a'*40,database=[],
            lag=dict(code=0,rows=[dict(group=g,topic=t,partition=0,lag=0) for g,t in
                [('log-group','log-topic'),('ai-service-group','ai-request-topic'),('ai-result-group','ai-result-topic'),('waf-detection-group','waf-detection-topic')]]),
            resources=dict(states=[dict(service='waf',image_id='image')]))
        r.remote_collector.collect=Mock(return_value=remote)
        page=Mock();page.goto=AsyncMock();page.locator.return_value.evaluate_all=AsyncMock()
        context=Mock();context.expose_binding=AsyncMock();context.add_init_script=AsyncMock();context.new_page=AsyncMock(return_value=page)
        browser=Mock(version='chrome');browser.new_context=AsyncMock(return_value=context);browser.close=AsyncMock()
        pw=Mock();pw.chromium.launch=AsyncMock(return_value=browser)
        manager=Mock();manager.__aenter__=AsyncMock(return_value=pw);manager.__aexit__=AsyncMock(return_value=None)
        client=dict(requestId='a'*32,phase='warmup',kind='background',sequence=999999,status=200,sent_ms=0)
        with (patch('playwright.async_api.async_playwright',return_value=manager),
                patch('run_ec2_e2e.login_ec2',new=AsyncMock()),patch('run_ec2_e2e.command',return_value=dict(stdout='k6',code=0)),
                patch('run_ec2_e2e.send_http',return_value=client),patch.object(r,'cmd',side_effect=AssertionError('LOCAL_DOCKER_FORBIDDEN'))):
            if failed:
                with self.assertRaisesRegex(RuntimeError,'FIXTURE_LOAD_FAILURE'): await r.execute()
            else: await r.execute()
        self.assertTrue(r.cleanup_ok)
        self.assertTrue(r.restored)
        self.assertEqual(r.setup.reconfigure.await_args_list[-1].args,('','restore'))
        self.assertEqual(browser.close.await_count,1)
        return r

    async def test_complete_remote_flow_does_not_call_local_compose(self):
        r=await self.flow()
        self.assertEqual([c.args[0] for c in r.database_observation.await_args_list],['preflight','before','after'])
        self.assertEqual(r.manifest['state'],'COMPLETED')

    async def test_load_exception_still_cleans_up_and_restores(self):
        await self.flow(failed=True)


class LagCadenceTests(unittest.IsolatedAsyncioTestCase):
    def experiment(self):
        exp=object.__new__(EC2Experiment)
        exp.lag_interval=60
        exp.force_lag=False
        exp.keys={('log-group','log-topic',0)}
        exp.last_lag_at=None
        return exp

    def test_lag_runs_first_then_only_every_interval_unless_forced(self):
        exp=self.experiment()
        with patch('run_ec2_e2e.time.perf_counter',return_value=100.0):
            self.assertTrue(exp.should_collect_lag())
            exp.last_lag_at=100.0
            self.assertFalse(exp.should_collect_lag())
            exp.force_lag=True
            self.assertTrue(exp.should_collect_lag())
        exp.force_lag=False
        with patch('run_ec2_e2e.time.perf_counter',return_value=159.9):
            self.assertFalse(exp.should_collect_lag())
        with patch('run_ec2_e2e.time.perf_counter',return_value=160.0):
            self.assertTrue(exp.should_collect_lag())
        exp.keys=set()
        with patch('run_ec2_e2e.time.perf_counter',return_value=101.0):
            self.assertTrue(exp.should_collect_lag())

    async def test_drain_always_collects_lag_and_restores_cadence_even_on_error(self):
        exp=self.experiment()
        seen=[]
        async def finished(recovery=False):
            seen.append((exp.force_lag,recovery))
            return True
        exp._drain=finished
        self.assertTrue(await exp.drain(recovery=True))
        self.assertEqual(seen,[(True,True)])
        self.assertFalse(exp.force_lag)
        async def failed(recovery=False):
            raise RuntimeError('drain failed')
        exp._drain=failed
        with self.assertRaises(RuntimeError):
            await exp.drain()
        self.assertFalse(exp.force_lag)
