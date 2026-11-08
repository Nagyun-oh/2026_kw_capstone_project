"""EC2 P8 고정 계약 실행기. pilot 1RPS/60초와 formal 단일 회차를 지원한다."""
import argparse
import asyncio
from datetime import datetime
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import sys
import time
import urllib.error

from ec2_load_policy import load_contract,selected_contract,assess,summarize_stage,knee_signals
from ec2_login import read_credentials,login_ec2
from ec2_watch import Ec2Guard,epoch_ms,load_observation_policy
from ec2_db import SSHDatabase
from e2e_core import fixture,client_record,epoch,ClockObservationError,parse_points
from e2e_environment import select_environment
from e2e_remote import SSHSettings,SSHCollection
from guard import stop_load
from metrics import resource_peaks
from pipeline import partition_keys,zero_lag,lag_maxima
from run_ec2_connection import ConnectionRun
from run_ec2_watch import combined_sample
from run_ec2_collection import local_git_state
from run_e2e import Experiment,build_request,request_opener,ResponseObservationError
from run_experiment import ROOT,HERE,KST,now,reserve,save,format_record_time,command


def send_http(phase,sequence,run_id,probe,clock,*,kind='probe'):
    env=select_environment('ec2')
    req=build_request(phase,sequence,run_id,probe,kind=kind,environment=env)
    sent,mono=epoch_ms(),time.perf_counter()
    try:
        response=request_opener(env).open(req,timeout=10)
    except urllib.error.HTTPError as error:
        response=error
    with response:
        if len(response.read(1048577))>1048576: raise RuntimeError('RESPONSE_TOO_LARGE')
        observation=dict(phase=phase,kind=kind,sequence=sequence,
            headers={'x-request-id':response.headers.get('X-Request-ID',''),
                     'x-dualguard-request-start':response.headers.get('X-DualGuard-Request-Start','')},
            status=response.code,duration_ms=(time.perf_counter()-mono)*1000,
            sent_ms=sent,ended_ms=epoch_ms(),c0=mono)
        try:
            return client_record(**observation,clock=clock)
        except ClockObservationError as error:
            # 이미 보낸 요청은 재전송하지 않고 안전한 시각·ID 필드만 재검증한다.
            error.observation=observation
            raise
        except ValueError:
            raise ResponseObservationError(response.code) from None


class LoadGuard(Ec2Guard):
    def summary(self):
        return dict(abort=self.abort,http_points=self.rules.http_count,collection_failures=self.rules.failures,
            stopped_owned_process=self.stopped,resource_baseline_confirmed=self.baseline is not None)


class EC2Experiment(Experiment):
    def __init__(self,args,contract,spec,probe,manifest,output,path,settings,credentials):
        super().__init__(args,spec,probe,manifest,output,path,ec2_contract=contract)
        self.contract,self.settings,self.credentials=contract,settings,credentials
        self.remote_collector=SSHCollection(settings)
        self.setup=ConnectionRun(settings,output,path,manifest)
        self.database_client=SSHDatabase(settings)
        self.db_observer=lambda run_id:self.database_client.collect(run_id,root_password=self.credentials.db_password)
        base,_=load_observation_policy()
        policy={**base,'stop':contract['stop']}
        self.guard=self.ec2_guard=LoadGuard(policy,sample_provider=lambda:combined_sample(self.setup.session))
        self.sampling_finished=asyncio.Event()
        self.collection_lock=asyncio.Lock()
        self.restored=False
        self.cleanup_ok=False
        self.load_started=False
        self.drain_elapsed=None
        self.log_id_floor=None
        # 계약 개정 3: 부하 중 lag 조회는 이 간격마다만 실행하고, 적체 해소 확인(drain)에서는 매번 실행한다.
        self.lag_interval=contract['workload']['lag_measurement_interval_seconds']
        self.force_lag=False
        # 계약 개정 4: 단계 모드는 포화 뒤 적체가 길 수 있어 원복 전 처리 정리 확인만 더 기다린다.
        self.recovery_drain_seconds=spec['workload']['recovery_drain_seconds']
        self.last_lag_at=None

    async def send_probe(self,phase,sequence):
        try:
            return await asyncio.to_thread(send_http,phase,sequence,self.manifest['id'],self.probe,self.clock_calibration)
        except ClockObservationError as error:
            if not await self.refresh_clock_observation():
                raise
            return client_record(**error.observation,clock=self.clock_calibration)

    async def read_client_points(self,points,*,partial=False):
        # 계약 개정 6: k6 일반 요청의 교차 시계 구간 이탈은 중단하지 않고 요청 기록(clock_window)에 남긴다.
        # 새 이탈이 보이면 드리프트 대응으로 기존 재보정을 먼저 시도한다(단계당 3회·300초 기한·불연속 중단 유지).
        # probe(파이썬 정밀 시각)와 보정 만료는 지금처럼 중단한다. 서버 지연은 서버 시계만 쓰므로 영향이 없다.
        if self.contract['clock_policy'].get('k6_background_window_mismatch')!='diagnostic':
            return await super().read_client_points(points,partial=partial)
        def parse():
            return parse_points(points,partial=partial,clock=self.clock_calibration,background_window_mismatch='record')
        try:
            rows=parse()
        except ClockObservationError:
            if not await self.refresh_clock_observation():
                raise
            return parse()
        fresh=[r for r in rows if r.get('clock_window') and (r['phase'],r['kind'],r['sequence']) not in self.seen_clients]
        if fresh and await self.refresh_clock_observation():
            rows=parse()
        return rows

    async def refresh_clock_observation(self):
        count=getattr(self,'clock_observation_rechecks',0)
        if count>=3:
            return False
        self.check_abort()
        previous=self.clock_calibration
        age=time.perf_counter()-previous['observed_monotonic']
        if age<0 or age>300:
            return False
        label=f'clock-recheck-{self.phase_name}-{count+1:02d}'
        await self.calibrate(label)
        fresh=self.clock_calibration
        # calibrated_at은 표시용이다. 정밀 UTC와 같은 교환에서 얻은 단조 시각을 비교한다.
        wall_ms=fresh['generator_reference_ms']-previous['generator_reference_ms']
        mono_ms=(fresh['observed_monotonic']-previous['observed_monotonic'])*1000
        if (abs(wall_ms-mono_ms)>10 or
                max(previous['offset_lower_ms'],fresh['offset_lower_ms'])>
                min(previous['offset_upper_ms'],fresh['offset_upper_ms'])):
            raise RuntimeError('CLOCK_RECHECK_DISCONTINUITY')
        fresh['previous_calibrations']=[
            {k:v for k,v in previous.items() if k!='previous_calibrations'},
            *previous.get('previous_calibrations',[])]
        self.clock_observation_rechecks=count+1
        self.manifest.setdefault('clock_rechecks',[]).append(dict(
            phase=self.phase_name,label=label,reason='ingress_outside_previous_interval',
            previous_lower_ms=previous['offset_lower_ms'],previous_upper_ms=previous['offset_upper_ms'],
            fresh_lower_ms=fresh['offset_lower_ms'],fresh_upper_ms=fresh['offset_upper_ms'],
            requests_resent=0))
        self.event('clock_recheck',label)
        self.check_abort()
        return True

    async def calibrate(self,label):
        await self.setup.recalibrate(label)
        self.clock_calibration=self.setup.clock
        width=self.clock_calibration['uncertainty_width_ms']
        self.manifest.setdefault('clock_diagnostics',[]).append(dict(label=label,uncertainty_width_ms=width,
            precise_cross_domain_reference=width<=self.contract['clock_policy']['precision_reference_width_ms'],
            role='diagnostic_only; server_latency_uses_server_clock; browser_latency_uses_pc_monotonic'))

    def should_collect_lag(self):
        if self.force_lag or not self.keys or self.last_lag_at is None:
            return True
        # 계약 개정 5: 간격이 null이면 부하 중에는 조회하지 않는다(해소 확인의 강제 조회만).
        if self.lag_interval is None:
            return False
        return time.perf_counter()-self.last_lag_at>=self.lag_interval

    async def collect(self):
        async with self.collection_lock:
            self.lag_requested=False
            try:
                snap=await super().collect()
            finally:
                # lag 조회를 요청한 수집이면 성공·실패와 관계없이 그 시각을 기록한다. 실패한 수집 직후
                # 다음 표본이 CLI를 다시 실행해 부하 중 CLI가 겹치던 문제(2026/11/08 13 RPS)를 막는다.
                if self.lag_requested:
                    self.last_lag_at=time.perf_counter()
            completed={t['requestId'] for t in self.traces if t['stage']=='AI_RESULT_COMMITTED'}
            pending=[c for c in self.clients if c['requestId'] not in completed]
            oldest=max(((epoch_ms()-c['sent_ms'])/1000 for c in pending),default=0)
            if self.load_started and oldest>self.contract['stop']['oldest_incomplete_request_seconds']:
                self.guard.rules.trip('oldest_incomplete','실험 요청의 미처리 시간이 60초를 초과했습니다.','FAIL',dict(seconds=oldest))
            return snap

    async def sampler(self):
        while not self.sampling_finished.is_set():
            try:
                await self.collect()
            except Exception as error:
                self.guard.collected('pipeline',False)
                self.errors.append('업무 계측 실패: '+type(error).__name__)
            try:
                await asyncio.wait_for(self.sampling_finished.wait(),timeout=10)
            except asyncio.TimeoutError:
                pass

    async def drain(self,*,recovery=False,limit=60):
        self.force_lag=True
        try:
            return await self._drain(recovery=recovery,limit=limit)
        finally:
            self.force_lag=False

    async def _drain(self,*,recovery=False,limit=60):
        started=time.perf_counter()
        zeros=0
        while time.perf_counter()-started<limit:
            if not recovery: self.check_abort()
            snap=await self.collect()
            ids={c['requestId'] for c in self.clients}
            completed={t['requestId'] for t in self.traces if t['stage']=='AI_RESULT_COMMITTED'}
            probe_ids={c['requestId'] for c in self.clients if c['kind']=='probe'}
            alerts={r['requestId']:r.get('alertId') for r in self.database}
            seen={(e.get('alertId'),s) for e in self.browser_events if e['kind']=='dom' for s in e.get('sources',[])}
            visible=all((alerts.get(r),s) in seen for r in probe_ids for s in ('AI','WAF'))
            zeros=zeros+1 if zero_lag(snap,self.keys) and ids<=completed and visible else 0
            self.drain_elapsed=time.perf_counter()-started
            if zeros>=2 and self.drain_elapsed<=limit: return True
            if limit-self.drain_elapsed<10: break
            await asyncio.sleep(10)
        return False

    async def guard_baseline(self):
        sample=await asyncio.to_thread(combined_sample,self.setup.session,clock_status=True)
        self.append('host-resources.jsonl',sample)
        if sample['ntp_synced'] is not True or not self.guard.preflight(sample):
            raise RuntimeError('EC2_START_CONDITION_FAILED')

    async def monitor(self):
        while not self.done:
            try:
                sample=await asyncio.to_thread(self.guard.resources)
                if sample is None: raise RuntimeError('RESOURCE_SAMPLE_FAILED')
                self.append('host-resources.jsonl',sample)
                value=await self.resource_input()
                self.resources.append(value)
                self.append('docker-stats.jsonl',value)
                self.guard.collected('browser',self.ready and time.perf_counter()-self.heartbeat<5)
            except Exception:
                self.guard.collected('resources',False)
            await asyncio.sleep(5)

    async def phase(self,phase,seconds,rate):
        self.clock_observation_rechecks=0
        self.manifest.setdefault('phase_times',{})[phase]=dict(started_at=now(),monotonic=time.perf_counter())
        if load_contract()[1]!=self.manifest['contract_sha256']:
            raise RuntimeError('CONTRACT_CHANGED_DURING_RUN')
        value=await super().phase(phase,seconds,rate)
        self.manifest['phase_times'][phase].update(ended_at=now(),elapsed_seconds=value)
        return value

    async def restore(self):
        if self.process and self.process.poll() is None:
            await asyncio.to_thread(stop_load,self.process)
        if self.setup.baseline is None:
            return
        if not self.clients and not self.setup.changed:
            self.cleanup_ok=self.restored=True
            return
        self.setup.page=self.page
        if self.clients and not self.final_lag:
            # 뒤늦은 결과가 IP를 재등록할 수 있어 처리 정리 확인을 먼저 한다.
            if not self.page or not await self.drain(recovery=True,limit=self.recovery_drain_seconds):
                raise RuntimeError('RESTORE_HELD_PROCESSING_NOT_DRAINED')
        await self.setup.cleanup(allowed_request_ids={c['requestId'] for c in self.clients})
        self.cleanup_ok=True
        if self.setup.changed:
            current=await self.setup.inspect('restore-precheck')
            if current['exclusions'] not in (self.setup.desired,self.setup.baseline['exclusions']):
                raise RuntimeError('EXTERNAL_EXCLUSION_CHANGE_REQUIRES_REVIEW')
            await self.setup.reconfigure(self.setup.baseline['exclusions'],'restore')
        await self.setup.recalibrate('clock-recovery')
        check=await asyncio.to_thread(send_http,'warmup',999998,self.manifest['id'],self.probe,
            self.setup.clock,kind='background')
        save(self.output/'recovery-http.json',check)
        if check['status']!=200: raise RuntimeError('RECOVERY_HTTP_NOT_200')
        deadline=time.perf_counter()+45
        while True:
            status=await self.setup.sync_status()
            if status.get('status')=='APPLIED' and status.get('stale') is False: break
            if time.perf_counter()>deadline: raise RuntimeError('RECOVERY_SYNC_UNCONFIRMED')
            await asyncio.sleep(5)
        self.restored=(self.setup.current['exclusions']==self.setup.baseline['exclusions'])
        self.setup.restored=self.restored
        self.setup.private_state()

    async def execute(self):
        from playwright.async_api import async_playwright
        self.manifest.update(state='RUNNING',started_at=now())
        self.setup.session.start()
        await self.guard_baseline()
        self.setup.baseline=await self.setup.inspect('baseline')
        from ec2_connection import with_generator
        self.setup.desired=with_generator(self.setup.baseline['exclusions'],self.setup.baseline['source_ipv4'])
        self.setup.private_state()
        before=await asyncio.to_thread(self.remote_collector.collect,self.manifest['id'],self.manifest['started_at'],mode='check')
        save(self.output/'remote-preflight.json',before)
        self.record_remote_collection(before)
        self.keys=partition_keys(before['lag'])
        if not zero_lag(before['lag'],self.keys) or before['database']: raise RuntimeError('INITIAL_LAG_OR_RUN_COLLISION')
        # 회차 시작 전 최대 로그 id. 이후 DB 수집은 이보다 큰 id만 읽는다(전체 JSON 스캔 제거, 시각 비의존).
        self.log_id_floor=self.manifest['log_id_floor']=before['log_id_floor']
        self.manifest['app_sha']=before['app_sha']
        self.manifest['images']=sorted(r['service']+' '+r['image_id'] for r in before['resources']['states'])
        self.manifest['versions']=dict(python=sys.version.split()[0],playwright=version('playwright'),
            k6=command(['k6','version'])['stdout'].strip())
        # 자격 증명 오류라면 WAF 변경·부하 전에 종료한다.
        await self.database_observation('preflight')
        async with async_playwright() as pw:
            browser=await pw.chromium.launch(channel='chrome',headless=False)
            self.manifest['versions']['browser']=browser.version
            monitor=sampler=None
            try:
                context=await browser.new_context(viewport=dict(width=1440,height=1000))
                await context.expose_binding('__dgBinding',self.binding)
                await context.add_init_script(path=str(HERE/'browser_trace.js'))
                self.page=await context.new_page()
                self.setup.page=self.page
                await self.page.goto(self.environment.dashboard_url,timeout=30000)
                await login_ec2(self.page,self.credentials)
                self.credentials.username=self.credentials.password=''
                print('관리자 로그인·STOMP 준비 완료. 이후 입력 없이 예비 측정·원복을 진행합니다.',flush=True)
                await self.calibrate('clock-source-check')
                calibration=await asyncio.to_thread(send_http,'warmup',999999,self.manifest['id'],self.probe,
                    self.clock_calibration,kind='background')
                self.add_client(calibration)
                if calibration['status']!=200: raise RuntimeError('SOURCE_CHECK_HTTP_NOT_200')
                deadline=time.perf_counter()+45
                while True:
                    state=await self.setup.inspect('https-source',request_id=calibration['requestId'])
                    if state['https_source'].get('rows'): break
                    if time.perf_counter()>deadline: raise RuntimeError('HTTPS_SOURCE_NOT_OBSERVED')
                    await asyncio.sleep(3)
                if state['https_source']!=dict(rows=1,matches=1): raise RuntimeError('HTTPS_SOURCE_CHANGED')
                await self.setup.reconfigure(self.setup.desired,'exclude')
                await self.calibrate('clock-warmup')
                await self.guard_baseline()
                monitor=asyncio.create_task(self.monitor())
                self.load_started=True
                await self.phase('warmup',self.manifest['warmup_seconds'],1)
                if not await self.drain(): raise RuntimeError('WARMUP_DRAIN_FAILED')
                await self.page.locator('[id^="request-alert-"] button[aria-label="close"]').evaluate_all('(nodes)=>nodes.forEach(n=>n.click())')
                await self.database_observation('before')
                await self.calibrate('clock-measurement')
                save(self.output/'manifest.json',self.manifest)
                sampler=asyncio.create_task(self.sampler())
                self.elapsed=await self.phase('measurement',self.manifest['seconds'],self.args.rate)
                self.sampling_finished.set()
                await sampler
                self.final_lag=await self.drain()
                self.manifest['final_drain_seconds']=self.drain_elapsed
                await self.database_observation('after')
                await self.table_check()
                after=await asyncio.to_thread(self.remote_collector.collect,self.manifest['id'],self.manifest['started_at'],
                    [c['requestId'] for c in self.clients],mode='check',expected_keys=self.keys,
                    log_id_floor=self.log_id_floor)
                save(self.output/'remote-after-measurement.json',after)
                self.record_remote_collection(after)
                images=sorted(r['service']+' '+r['image_id'] for r in after['resources']['states'])
                if after['app_sha']!=self.manifest['app_sha'] or images!=self.manifest['images']:
                    self.guard.rules.trip('target_changed','측정 중 대상 SHA·이미지가 변경됐습니다.','INCONCLUSIVE',{})
                self.check_abort()
                self.manifest['state']='COMPLETED'
            finally:
                self.sampling_finished.set()
                if sampler: await asyncio.gather(sampler,return_exceptions=True)
                self.done=True
                if monitor: await asyncio.gather(monitor,return_exceptions=True)
                try:
                    await self.restore()
                except Exception as error:
                    self.errors.append('원복 미확인: '+(str(error) if type(error) is RuntimeError else type(error).__name__))
                await browser.close()


def report(m,r):
    title={'pilot':'예비 측정','step':'단계 부하'}.get(m['mode'],'기준 측정')
    lines=[f"# 실험 기록: {format_record_time(m['planned_at']).split()[0]} — EC2 {title}",'',
        '[EC2 목차](../README.md) · [P8](../P8.md)','', '## 실행 정보',f"- ID: `{m['id']}`",
        f"- 실행 / 판정: {m['state']} / {r.get('verdict','NOT_EVALUATED')}",
        f"- 시작 / 종료: {format_record_time(m.get('started_at'))} / {format_record_time(m.get('ended_at'))}",
        f"- 구분: {m['mode']} / 입력 {m['rate']} RPS / 측정 {m['seconds']}초 / 워밍업 {m['warmup_seconds']}초 제외",
        f"- 원본: `build/test-runs/{m['id']}/`",'## S — Situation','- Windows 발생기에서 실제 HTTPS 경로와 EC2 비동기 파이프라인을 관측한다.',
        '## T — Task·Target','- AI·WAF 요청 발생→커밋 p95 각각 3초, 정합성·단일 알림·60초 내 처리 완료/lag 해소.',
        '- HTTP·브라우저 지연과 p50/p99는 별도 참고. 예비 측정은 정식 기준선·반복 PASS로 사용하지 않는다.',
        '## A — Action','- 입력은 숨김으로 받고 메모리에서만 사용. 임시 단일 IP 제외·원래 설정 복구.',
        '- warmup→drain→DB 전 관측→measurement→drain→DB 후 관측→대표 행→정리·원복.',
        '## R — Result','| 구간 | 수 | 평균 ms | p50 ms | p95 ms | p99 ms | 최대 ms |',
        '| --- | --- | --- | --- | --- | --- | --- |']
    def n(v): return '미측정' if v is None else str(round(v,3))
    for k,s in r.get('stats_ms',{}).items():
        lines.append('| '+' | '.join([k,str(s['count'])]+[n(s[t]) for t in ('avg_ms','p50_ms','p95_ms','p99_ms','max_ms')])+' |')
    if r.get('knee_signals'):
        lines += ['','- 한계 신호(단계 부하): '+json.dumps(r['knee_signals'],ensure_ascii=False)]
    if r.get('clock_window_diagnostics'):
        d=r['clock_window_diagnostics']
        lines += ['',f"- 교차 시계 진단(k6 일반 요청, 중단하지 않음·서버 지연 판정과 무관): 구간 이탈 {d['outside']}건"
                  f"(측정 {d['measurement_outside']}건), 최대 초과 {d['max_excess_ms']}ms"]
    lines += ['','- 입력·처리량: '+json.dumps(r.get('rates',{}),ensure_ascii=False),
        '- 정합성: '+json.dumps(r.get('counts',{}),ensure_ascii=False),
        *['- '+x for x in r.get('reasons',[])],
        '## T — Trouble·복구',f"- 시험 등록 정리: {m.get('cleanup_ok')} / 원래 제외 설정 복구: {m.get('configuration_restored')}",
        '- DB 전후 통계는 관측·관리자 조회·다른 트래픽을 포함한 전체 DB 구간이며 실험 요청만의 쿼리 수로 표현하지 않는다.',
        '- CPU 크레딧은 P0 사용자 콘솔 자료(과거 시각)와 이번 최신 미수집을 구분한다.',
        '- 부하 중 처리 완료 EPS·lag 추이는 progress.jsonl, 자원은 host-resources.jsonl·docker-stats.jsonl을 참고한다.']
    return '\n'.join(lines)+'\n'


def main(argv=None, *, prepared_credentials=None):
    p=argparse.ArgumentParser(description=__doc__)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run',action='store_true')
    mode.add_argument('--execute',action='store_true')
    p.add_argument('--mode',choices=('pilot','formal','step'),default='pilot')
    # 허용 RPS는 계약에서 검증한다: pilot 1, formal 1·3·5, step 7·9·11·13(개정 4).
    p.add_argument('--rate',type=int,default=1)
    p.add_argument('--round',type=int,default=1)
    p.add_argument('--ssh-host')
    p.add_argument('--identity-file',type=Path)
    p.add_argument('--host-key-alias')
    p.add_argument('--prompt-credentials',action='store_true')
    a=p.parse_args(argv)
    if not 1<=a.round<=99: p.error('회차는 1~99입니다.')
    contract,digest=load_contract()
    try:
        spec=selected_contract(contract,a.mode,a.rate)
    except ValueError:
        p.error('계약에 없는 모드·RPS 조합입니다. pilot 1, formal 1·3·5, step 7·9·11·13만 허용합니다.')
    a.runtime_environment=select_environment('ec2')
    scenario={'pilot':'ec2-pilot','step':f'ec2-step-rps{a.rate}'}.get(a.mode,f'ec2-e2e-rps{a.rate}')
    rid=datetime.now(KST).strftime('%Y%m%dT%H%M%S%z')+f'-{scenario}-r{a.round:02d}'
    probe,fixture_hash=fixture()
    m=dict(id=rid,schema='ec2-e2e-v1',environment='ec2',mode=a.mode,planned_at=now(),state='PLANNED',
        rate=a.rate,seconds=spec['workload']['measurement_seconds'],warmup_seconds=30,
        contract_sha256=digest,contract_revision=contract['revision'],fixture_sha256=fixture_hash,target_url=a.runtime_environment.target_url,
        dashboard_url=a.runtime_environment.dashboard_url,ip_policy_confirmed=True,
        latest_cpu_credit='NOT_SAMPLED_P0_CONSOLE_IS_HISTORICAL',expected_measurement_requests=a.rate*spec['workload']['measurement_seconds'])
    if a.dry_run:
        print(json.dumps(m,ensure_ascii=False,indent=2))
        return 0
    if not a.ssh_host or not a.identity_file or not a.identity_file.is_file() or not a.prompt_credentials:
        p.error('기존 SSH 호스트·키와 --prompt-credentials가 필요합니다. 비밀번호를 인자로 전달하지 마세요.')
    output,path=reserve(ROOT,rid,'ec2')
    m.update(local_git_state())
    m['runner_files_sha256']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in HERE.iterdir() if f.suffix in ('.py','.js')}
    save(output/'measurement-contract.json',spec)
    save(output/'manifest.json',m)
    path.write_text(report(m,{}),encoding='utf-8')
    credentials=None
    experiment=None
    try:
        credentials=prepared_credentials or read_credentials()
        settings=SSHSettings(a.ssh_host,a.identity_file,a.host_key_alias)
        experiment=EC2Experiment(a,contract,spec,probe,m,output,path,settings,credentials)
        asyncio.run(experiment.execute())
    except (Exception,KeyboardInterrupt) as error:
        m['state']='ABORTED' if experiment and experiment.clients else 'BLOCKED'
        if experiment:
            experiment.errors.append('실행 미완료: '+(str(error) if type(error) is RuntimeError else type(error).__name__))
    finally:
        if credentials: credentials.clear()
        if experiment:
            experiment.setup.session.close()
            if experiment.process and experiment.process.poll() is None: stop_load(experiment.process)
            m.update(cleanup_ok=experiment.cleanup_ok,configuration_restored=experiment.restored,ended_at=now())
            r=assess(experiment.clients,experiment.traces,experiment.database,experiment.browser_events,spec,
                rate=a.rate,elapsed=experiment.elapsed,final_lag=experiment.final_lag,errors=experiment.errors,
                abort=experiment.guard.abort,complete=m['state']=='COMPLETED' and not experiment.errors)
            if not experiment.restored and r['verdict']=='PASS':
                r.update(verdict='INCONCLUSIVE',reasons=['원복 미확인'])
            r.update(resource_peaks=resource_peaks(experiment.resources),lag_maxima=lag_maxima(experiment.snapshots),guard=experiment.guard.summary())
            # 계약 개정 6: k6 일반 요청의 교차 시계 구간 이탈을 숨기지 않고 건수·최대 초과량으로 남긴다.
            outside=[c for c in experiment.clients if c.get('clock_window')]
            r['clock_window_diagnostics']=dict(policy=contract['clock_policy'].get('k6_background_window_mismatch','abort'),
                outside=len(outside),measurement_outside=sum(1 for c in outside if c['phase']=='measurement'),
                max_excess_ms=max((c['clock_window']['excess_ms'] for c in outside),default=None),
                samples=[dict(phase=c['phase'],sequence=c['sequence'],excess_ms=c['clock_window']['excess_ms'])
                         for c in outside[:20]])
            if a.mode=='step':
                # 계약 개정 4: 송신 구간의 처리 완료 비율·미처리 기울기·서버 p95·해소 시간으로 한계 신호를 기록한다.
                try:
                    progress=output/'progress.jsonl'
                    rows=[json.loads(line) for line in progress.read_text(encoding='utf-8').splitlines() if line.strip()] if progress.exists() else []
                    r['knee_signals']=knee_signals(rows,rate=a.rate,expected=m['expected_measurement_requests'],
                        stats_ms=r.get('stats_ms'),drain_seconds=experiment.drain_elapsed if experiment.final_lag else None,
                        criteria=contract['knee_criteria'])
                except (OSError,ValueError,KeyError,TypeError) as error:
                    r['knee_signals']=dict(status='ERROR',error=type(error).__name__)
        else:
            m.update(state='BLOCKED',ended_at=now(),cleanup_ok=False,configuration_restored=False)
            r=dict(verdict='INCONCLUSIVE',reasons=['숨김 입력 또는 실행 준비 미완료'])
        r['evidence_sha256']={str(f.relative_to(output)):hashlib.sha256(f.read_bytes()).hexdigest()
            for f in output.rglob('*') if f.is_file() and not f.name.startswith('private') and f.name not in ('manifest.json','metrics.json')}
        save(output/'manifest.json',m)
        save(output/'metrics.json',r)
        path.write_text(report(m,r),encoding='utf-8')
        print('결과: '+r['verdict'])
        print('보고서: '+str(path))
    return 0 if r['verdict']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
