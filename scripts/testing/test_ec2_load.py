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

from ec2_load_policy import load_contract,selected_contract,validate_contract,assess,summarize_stage,knee_signals
from ec2_login import Credentials,read_credentials,login_ec2
from e2e_core import evaluate,ClockObservationError
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

    def test_contract_revision_6_records_background_clock_mismatch(self):
        self.assertEqual(self.policy['revision'],6)
        self.assertEqual(self.policy['clock_policy']['k6_background_window_mismatch'],'diagnostic')
        for value in ('missing','abort','ignore'):
            changed=copy.deepcopy(self.policy)
            if value=='missing': del changed['clock_policy']['k6_background_window_mismatch']
            else: changed['clock_policy']['k6_background_window_mismatch']=value
            with self.assertRaises(ValueError): validate_contract(changed)

    def test_contract_keeps_step_mode_and_turns_off_lag_during_load(self):
        self.assertEqual(self.policy['workload']['step_rates_per_second'],[7,9,11,13])
        self.assertEqual(self.policy['workload']['step_max_vus'],20)
        self.assertEqual(selected_contract(self.policy,'step',9)['workload']['measurement_seconds'],120)
        for mode,rate in (('step',5),('step',15),('formal',7),('pilot',7)):
            with self.assertRaises(ValueError): selected_contract(self.policy,mode,rate)
        for key,value in (('step_rates_per_second',[7,9,11,13,15]),('step_max_vus',50)):
            changed=copy.deepcopy(self.policy)
            changed['workload'][key]=value
            with self.assertRaises(ValueError): validate_contract(changed)
        changed=copy.deepcopy(self.policy)
        changed['knee_criteria']['completion_ratio_below']=0.5
        with self.assertRaises(ValueError): validate_contract(changed)
        self.assertIsNone(self.policy['workload']['lag_measurement_interval_seconds'])
        self.assertEqual(self.policy['workload']['lag_confirmation_interval_seconds'],10)
        for value in ('missing',60,10):
            changed=copy.deepcopy(self.policy)
            if value=='missing': del changed['workload']['lag_measurement_interval_seconds']
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

    def test_step_plan_uses_separate_ids_and_rejects_rates_outside_contract(self):
        out=io.StringIO()
        with patch('run_ec2_e2e.reserve') as reserve,contextlib.redirect_stdout(out):
            self.assertEqual(main(['--dry-run','--mode','step','--rate','9']),0)
        plan=json.loads(out.getvalue())
        self.assertIn('-ec2-step-rps9-r01',plan['id'])
        self.assertEqual((plan['mode'],plan['rate'],plan['expected_measurement_requests']),('step',9,1080))
        reserve.assert_not_called()
        for argv in (['--mode','step','--rate','5'],['--mode','formal','--rate','9']):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                main(['--dry-run',*argv])


def progress(points,start=datetime(2026,11,8,3,tzinfo=timezone.utc).timestamp()):
    """(경과 초, 측정 HTTP 수, AI 완료 수) 목록을 progress.jsonl 행 모양으로 만든다."""
    return [dict(at=datetime.fromtimestamp(start+t,timezone.utc).isoformat(),
                 counts=dict(measurement=dict(http=h,AI_RESULT_COMMITTED=a,pending_ai=h-a)))
            for t,h,a in points]


class KneeSignalTests(unittest.TestCase):
    def setUp(self): self.policy,_=load_contract()

    def test_sustained_step_has_no_knee_signal(self):
        rows=progress([(0,0,0)]+[(10*i,90*i,90*i-3) for i in range(1,13)]+[(130,1080,1080)])
        r=knee_signals(rows,rate=9,expected=1080,stats_ms=dict(ai_server=dict(p95_ms=420),waf_server=dict(p95_ms=300)),
                       drain_seconds=20,criteria=self.policy['knee_criteria'])
        self.assertEqual(r['status'],'EVALUATED')
        self.assertFalse(r['knee'])
        self.assertAlmostEqual(r['completion_ratio'],1.0,places=2)
        self.assertEqual(r['backlog_clear_seconds_after_send'],10.0)

    def test_falling_behind_triggers_ratio_slope_and_drain_reasons(self):
        rows=progress([(10*i,130*i,104*i) for i in range(1,13)])
        r=knee_signals(rows,rate=13,expected=1560,stats_ms=dict(ai_server=dict(p95_ms=3500)),drain_seconds=None,
                       criteria=self.policy['knee_criteria'])
        self.assertTrue(r['knee'])
        self.assertAlmostEqual(r['completion_ratio'],0.8,places=2)
        self.assertGreater(r['pending_slope_per_second'],0.05*13)
        self.assertEqual(len(r['reasons']),4)

    def test_too_few_samples_is_not_judged(self):
        r=knee_signals(progress([(10,90,90),(20,180,175)]),rate=9,expected=1080,criteria=self.policy['knee_criteria'])
        self.assertEqual(r['status'],'INSUFFICIENT_SAMPLES')
        self.assertIsNone(r['knee'])


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
        # k6는 반복 함수의 예외를 로그로만 남기고 종료 코드 0을 돌려준다. 단언 실패를 로그로 잡는다.
        output=result.stdout+result.stderr
        self.assertNotIn('script exception',output,output)
        self.assertNotIn('level=error',output,output)


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
        remote=dict(transport={},commands=[],collection_status='COLLECTED',errors=[],app_sha='a'*40,database=[],log_id_floor=36475,
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
        # 시작 전 check 수집은 하한 없이(충돌 확인용 전체 조회), 이후 수집은 시작 전 최대 id를 하한으로 쓴다.
        calls=r.remote_collector.collect.call_args_list
        self.assertIsNone(calls[0].kwargs.get('log_id_floor'))
        self.assertTrue(calls[1:] and all(c.kwargs.get('log_id_floor')==36475 for c in calls[1:]))
        self.assertEqual(r.manifest['log_id_floor'],36475)

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
        async def finished(recovery=False,limit=60):
            seen.append((exp.force_lag,recovery,limit))
            return True
        exp._drain=finished
        self.assertTrue(await exp.drain(recovery=True))
        self.assertEqual(seen,[(True,True,60)])
        self.assertFalse(exp.force_lag)
        async def failed(recovery=False,limit=60):
            raise RuntimeError('drain failed')
        exp._drain=failed
        with self.assertRaises(RuntimeError):
            await exp.drain()
        self.assertFalse(exp.force_lag)

    def test_null_interval_skips_lag_during_load_but_not_when_forced_or_unkeyed(self):
        exp=self.experiment()
        exp.lag_interval=None
        exp.last_lag_at=100.0
        with patch('run_ec2_e2e.time.perf_counter',return_value=10_000.0):
            self.assertFalse(exp.should_collect_lag())
            exp.force_lag=True
            self.assertTrue(exp.should_collect_lag())
            exp.force_lag=False
            exp.keys=set()
            self.assertTrue(exp.should_collect_lag())

    async def test_failed_collection_still_counts_as_lag_attempt(self):
        # 2026/11/08 13 RPS: DB 수집 실패 뒤 lag 조회 시각이 갱신되지 않아 25초 만에 CLI가 다시 실행됐다.
        exp=self.experiment()
        exp.collection_lock=asyncio.Lock()
        async def failing():
            exp.lag_requested=exp.should_collect_lag()
            raise RuntimeError('원격 수집 불완전: DATABASE_UNAVAILABLE')
        with patch('run_e2e.Experiment.collect',side_effect=failing),patch('run_ec2_e2e.time.perf_counter',return_value=100.0):
            with self.assertRaises(RuntimeError):
                await exp.collect()
        self.assertEqual(exp.last_lag_at,100.0)
        with patch('run_e2e.Experiment.collect',side_effect=failing),patch('run_ec2_e2e.time.perf_counter',return_value=125.0):
            with self.assertRaises(RuntimeError):
                await exp.collect()
        self.assertEqual(exp.last_lag_at,100.0)


class BackgroundClockDiagnosticTests(unittest.IsolatedAsyncioTestCase):
    """계약 개정 6: k6 일반 요청의 교차 시계 구간 이탈은 중단하지 않고 기록하며, 새 이탈마다 재보정을 먼저 시도한다."""

    def setUp(self):
        import tempfile
        from ec2_watch import calibrate
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.points=Path(self.temp.name)/'measurement-points.jsonl'
        rows=[('a'*32,'1.355',1),('b'*32,'1.400',2)]  # 두 번째는 응답 수신보다 늦은 WAF 시작 시각
        self.points.write_text(''.join(json.dumps(dict(type='Point',metric='dg_client_request',data=dict(value=12,tags=dict(
            phase='measurement',kind='background',sequence=str(seq),request_id=rid,ingress=ingress,status='200',
            sent_at_ms='1000',ended_at_ms='1012'))))+'\n' for rid,ingress,seq in rows),encoding='utf-8')
        exchange=dict(client_sent_ms=1000,client_received_ms=1012,server_received_ms=1355,server_sent_ms=1357,
                      roundtrip_ms=12,observed_monotonic=1)
        policy,_=load_contract()
        self.exp=object.__new__(EC2Experiment)
        self.exp.contract=policy
        self.exp.clock_calibration=calibrate([exchange]*3)
        self.exp.seen_clients=set()
        self.exp.refresh_clock_observation=AsyncMock(return_value=True)

    async def test_mismatch_is_recorded_and_recheck_runs_once_per_new_row(self):
        with patch('ec2_watch.time.perf_counter',return_value=2):
            rows=await self.exp.read_client_points(self.points,partial=True)
            self.assertEqual([('clock_window' in r) for r in rows],[False,True])
            self.assertEqual(self.exp.refresh_clock_observation.await_count,1)
            self.exp.seen_clients={(r['phase'],r['kind'],r['sequence']) for r in rows}
            await self.exp.read_client_points(self.points)
        self.assertEqual(self.exp.refresh_clock_observation.await_count,1)

    async def test_contract_without_diagnostic_policy_keeps_abort(self):
        self.exp.contract=copy.deepcopy(self.exp.contract)
        self.exp.contract['clock_policy']['k6_background_window_mismatch']='abort'
        self.exp.refresh_clock_observation=AsyncMock(return_value=False)
        with patch('ec2_watch.time.perf_counter',return_value=2),self.assertRaises(ClockObservationError):
            await self.exp.read_client_points(self.points)


class RecoveryDrainTests(unittest.IsolatedAsyncioTestCase):
    """계약 개정 4: 측정 후 해소 판정은 60초, 단계 모드의 원복 전 처리 정리 확인만 300초까지 기다린다."""

    def test_only_step_mode_extends_recovery_drain(self):
        policy,_=load_contract()
        self.assertEqual(selected_contract(policy,'step',11)['workload']['recovery_drain_seconds'],300)
        for mode,rate in (('pilot',1),('formal',5)):
            self.assertEqual(selected_contract(policy,mode,rate)['workload']['recovery_drain_seconds'],60)
        changed=copy.deepcopy(policy)
        changed['workload']['step_recovery_drain_seconds']=900
        with self.assertRaises(ValueError): validate_contract(changed)

    async def test_drain_waits_until_given_limit_without_backlog_clearing(self):
        exp=object.__new__(EC2Experiment)
        exp.force_lag=False;exp.keys=set();exp.clients=[dict(requestId='a'*32,kind='background')]
        exp.traces=[];exp.database=[];exp.browser_events=[];exp.check_abort=Mock()
        clock=[0.0];calls=[]
        async def collect():
            calls.append(clock[0]);return None
        async def sleep(seconds): clock[0]+=seconds
        exp.collect=collect
        with (patch('run_ec2_e2e.time.perf_counter',side_effect=lambda:clock[0]),
                patch('run_ec2_e2e.asyncio.sleep',side_effect=sleep),patch('run_ec2_e2e.zero_lag',return_value=False)):
            self.assertFalse(await exp.drain())
            self.assertEqual(len(calls),6)
            clock[0]=0.0;calls.clear()
            self.assertFalse(await exp.drain(recovery=True,limit=300))
            self.assertEqual(len(calls),30)

    async def test_restore_uses_recovery_limit_and_holds_exclusion_when_not_drained(self):
        from types import SimpleNamespace
        exp=object.__new__(EC2Experiment)
        exp.process=None;exp.page=Mock();exp.final_lag=False;exp.recovery_drain_seconds=300
        exp.clients=[dict(requestId='a'*32)]
        exp.setup=SimpleNamespace(baseline=dict(exclusions=''),changed=True,cleanup=AsyncMock(),reconfigure=AsyncMock())
        exp.drain=AsyncMock(return_value=False)
        with self.assertRaisesRegex(RuntimeError,'RESTORE_HELD_PROCESSING_NOT_DRAINED'):
            await exp.restore()
        exp.drain.assert_awaited_once_with(recovery=True,limit=300)
        exp.setup.cleanup.assert_not_awaited();exp.setup.reconfigure.assert_not_awaited()
