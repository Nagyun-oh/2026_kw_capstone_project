"""P7: EC2 정상 3건·탐지 1건·복구 1건의 실제 브라우저 연결 확인."""
import argparse
import asyncio
from datetime import datetime
import hashlib
import json
from pathlib import Path
import time

from ec2_connection import Control, RequestBudget, connection_checks, owned_blacklist, public_state, with_generator, observe_threat_row
from ec2_watch import WatchSession, Ec2Guard, calibrate, load_observation_policy
from e2e_core import browser_record, fixture
from e2e_environment import select_environment
from e2e_remote import SSHCollection, SSHSettings, HERE
from pipeline import zero_lag, partition_keys
from run_ec2_collection import local_git_state
from run_ec2_watch import combined_sample
from run_experiment import ROOT, KST, now, reserve, save, format_record_time


class ConnectionRun:
    def __init__(self, settings, output, report_path, manifest):
        self.settings, self.output, self.path, self.manifest = settings, output, report_path, manifest
        self.control, self.collector = Control(settings), SSHCollection(settings)
        self.policy, self.policy_hash = load_observation_policy()
        self.session, self.guard = WatchSession(settings), Ec2Guard(self.policy)
        self.fixture, self.fixture_hash = fixture()
        self.budget = RequestBudget()
        self.clients, self.events, self.database, self.traces = [], [], [], []
        self.baseline, self.desired, self.current = None, None, None
        self.changed, self.restored, self.cleanup_ok = False, False, False
        self.page, self.ready, self.stop_monitor = None, False, False
        self.pause_monitor, self.monitor_error = False, None
        self.clock, self.probe_id = None, None
        self.checks, self.errors = {}, []
        self.counter = 0
        self.keys = set()
        self.observation_lock = asyncio.Lock()

    def persist(self):
        save(self.output/'manifest.json', self.manifest)
        save(self.output/'summary.json', dict(checks=self.checks, errors=self.errors,
            connection_verdict=self.manifest['connection_verdict'], performance_verdict='NOT_EVALUATED',
            requests=len(self.clients), cleanup_ok=self.cleanup_ok, configuration_restored=self.restored))
        self.path.write_text(self.report(), encoding='utf-8')

    def report(self):
        m = self.manifest
        lines = [f"# 실험 기록: {format_record_time(m['planned_at']).split()[0]} — P7 EC2 소량 연결", '',
            '[EC2 목차](../README.md) · [P7 가이드](../P7.md)', '', '## 실행 정보',
            f"- ID: `{m['id']}`", f"- 상태: {m['state']} / 연결 판정: {m['connection_verdict']}",
            '- 성능 판정: NOT_EVALUATED',
            f"- 시작 / 종료: {format_record_time(m.get('started_at'))} / {format_record_time(m.get('ended_at'))}",
            f"- 원본: `build/test-runs/{m['id']}/`", '', '## S — Situation',
            '- Windows 발생기 → 실제 HTTPS → EC2 WAF·비동기 파이프라인 → 관리자 Chrome 연결을 확인한다.',
            '## T — Task', '- 서버 requestId·DB·alertId·실제 수신·알림 DOM을 연결한다.',
            '## T — Target', '- 정상 3건과 검증 fixture 1건. 복구 후 정상 1건. 정합성·인증·설정 복구 확인이며 부하 실험이 아니다.',
            '- 발생기 단일 IPv4만 기존 제외 목록에 추가. 원래 제외 목록과 기존 블랙리스트를 보존한다.',
            '- 브라우저 로그인은 사용자가 직접 수행. 비밀번호·쿠키·세션 파일·응답 본문을 저장하지 않는다.',
            '## A — Action', f"- 기록된 HTTP 요청: {len(self.clients)}건 / probe 전송 시도: {self.budget.probes}건.",
            '- 임시 제외 적용·복구는 WAF 서비스만 재생성. .env.aws·앱 코드·DB 스키마는 변경하지 않는다.',
            '## R — Result', '| 확인 | 결과 |', '| --- | --- |']
        lines += [f'| {key} | {"확인" if value else "미확인"} |' for key,value in self.checks.items()]
        lines += ['', f'- 이번 실험의 블랙리스트 정리 확인: {self.cleanup_ok}',
            f'- WAF 원래 제외 설정·건강 상태 복구 확인: {self.restored}',
            '## T — Trouble·복구', *['- '+e for e in self.errors],
            '- 연결 PASS는 탐지 정확도·성능 SLO·전체 장애 복구 PASS를 의미하지 않는다.',
            '- 재시작은 실험 준비·복구를 위한 의도적 WAF 재생성이다. 감시 기준선은 각 변경 뒤 새로 확인한다.',
            '- private-state.json은 발생기 IP·기존 제외 목록을 포함하는 Git 제외 복구 기록이다. 공유하지 않는다.']
        return '\n'.join(lines)+'\n'

    def private_state(self):
        data = dict(baseline=self.baseline, desired=self.desired, changed=self.changed,
            restored=self.restored, current=self.current, probe_id=self.probe_id, run_id=self.manifest['id'])
        temp = self.output/'private-state.tmp'
        save(temp, data)
        temp.replace(self.output/'private-state.json')

    async def inspect(self, label, **kwargs):
        if self.baseline:
            kwargs['source_ipv4'] = self.baseline['source_ipv4']
        value = await asyncio.to_thread(self.control.call, **kwargs)
        self.counter += 1
        save(self.output/(label+f'-{self.counter:03d}.json'), public_state(value))
        if value.get('private'):
            self.current = value['private']
        if value.get('status') != 'OK':
            raise RuntimeError(value.get('error_code', 'CONTROL_FAILED'))
        return self.current

    async def sample(self, label, *, reset=False):
        row = await asyncio.to_thread(combined_sample, self.session, clock_status=reset)
        save(self.output/(label+'.json'), row)
        if reset:
            self.guard = Ec2Guard(self.policy)
            if row.get('ntp_synced') is not True or not self.guard.preflight(row):
                raise RuntimeError('P5_START_CONDITION_FAILED')
        else:
            self.guard.observe(row)
        if self.guard.abort:
            raise RuntimeError('P5_GUARD_ABORT')
        return row

    async def recalibrate(self, label):
        exchanges = []
        for _ in range(self.policy['clock_samples']):
            exchanges.append(await asyncio.to_thread(self.session.exchange, 'clock'))
        save(self.output/(label+'.json'), dict(calibration=None, exchanges=exchanges))
        try:
            self.clock = calibrate(exchanges)
        except ValueError as error:
            raise RuntimeError('CLOCK_CALIBRATION_FAILED: '+str(error)) from None
        save(self.output/(label+'.json'), dict(calibration=self.clock, exchanges=exchanges))

    async def monitor(self):
        i = 0
        while not self.stop_monitor:
            await asyncio.sleep(5)
            if self.pause_monitor or self.stop_monitor:
                continue
            try:
                async with self.observation_lock:
                    if self.pause_monitor or self.stop_monitor:
                        continue
                    i += 1
                    await self.sample(f'resource-{i:03d}')
            except Exception:
                self.monitor_error = 'P5_RESOURCE_OBSERVATION_FAILED_OR_ABORT'
                return

    def check_monitor(self):
        if self.monitor_error:
            raise RuntimeError(self.monitor_error)

    async def send(self, sequence, *, probe=False, recovery=False):
        self.check_monitor()
        value = await asyncio.to_thread(self.budget.send, self.manifest['id'], self.fixture,
            sequence, self.clock, probe=probe, recovery=recovery)
        self.clients.append(value)
        save(self.output/'client-requests.json', self.clients)
        if probe:
            self.probe_id = value['requestId']
            self.private_state()
        if value['status'] != 200:
            raise RuntimeError('UNEXPECTED_HTTP_'+str(value['status']))
        return value

    async def collect(self, label):
        self.check_monitor()
        value = await asyncio.to_thread(self.collector.collect, self.manifest['id'], self.manifest['started_at'],
            [c['requestId'] for c in self.clients], mode='pipeline')
        save(self.output/(label+'.json'), value)
        if value['collection_status'] != 'COLLECTED':
            raise RuntimeError('PIPELINE_COLLECTION_INCOMPLETE')
        self.database = value['database']
        self.traces = value['traces']
        return value

    async def reconfigure(self, desired, label):
        async with self.observation_lock:
            return await self._reconfigure(desired, label)

    async def _reconfigure(self, desired, label):
        self.pause_monitor = True
        before = await self.inspect(label+'-before')
        if before['exclusions'] == desired:
            self.pause_monitor = False
            return
        # 변경 시도 전에 복구 책임을 기록한다. timeout도 실제 상태를 다시 확인한다.
        self.changed = True
        self.private_state()
        value = await asyncio.to_thread(self.control.call, 'reconfigure', source_ipv4=self.baseline['source_ipv4'],
            expected_sha=self.baseline['app_sha'], expected_waf_id=before['waf']['id'],
            expected_exclusions=before['exclusions'], desired_exclusions=desired)
        save(self.output/(label+'-command.json'), public_state(value))
        if value['status'] != 'OK':
            raise RuntimeError(value.get('error_code','RECONFIGURE_FAILED'))
        deadline = time.monotonic()+90
        while time.monotonic() < deadline:
            await asyncio.sleep(3)
            after = await self.inspect(label+'-after')
            self.private_state()
            if (after['exclusions']==desired and after['nginx_test_ok'] and
                    after['waf']['running'] and after['waf']['health']=='healthy'):
                await self.sample(label+'-resource', reset=True)
                self.pause_monitor = False
                return
        raise RuntimeError('WAF_RECONFIGURE_NOT_CONFIRMED')

    def binding(self, source, value):
        if source.get('frame') != self.page.main_frame:
            return
        try:
            row = browser_record(value, time.perf_counter())
        except (ValueError, TypeError):
            return
        if row['kind']=='ready': self.ready = True
        if row['kind']=='disconnected': self.ready = False
        if row['kind'] in ('received','dom'):
            self.events.append(row)
            save(self.output/'browser-events.json', self.events)

    async def sync_status(self):
        # 제외 IP 원문은 브라우저 내부에서 비교하고 불리언·사유 코드만 반환한다.
        value = await self.page.evaluate('''async (source) => {
          const r=await fetch('/api/v1/waf/sync-status',{credentials:'include',cache:'no-store'});
          if(!r.ok) return {http:r.status};
          const d=await r.json();
          const e=Array.isArray(d.excludedIps)?d.excludedIps.find(x=>x.ip===source):null;
          return {http:r.status,status:d.status,stale:d.stale,receivedAt:d.receivedAt,
            checkedAt:d.checkedAt,lastSyncResult:d.lastSyncResult,
            versionsMatch:d.currentVersion===d.appliedVersion,
            generatorExcluded:!!e,generatorReason:e?.reason??null};
        }''', self.baseline['source_ipv4'])
        self.counter += 1
        save(self.output/f'sync-status-{self.counter:03d}.json', value)
        return value

    async def cleanup(self, *, allowed_request_ids=None):
        current = await self.inspect('cleanup-before')
        if allowed_request_ids is None:
            ids = owned_blacklist(self.baseline['blacklist'], current['blacklist'], self.manifest['id'], self.probe_id)
        else:
            old={r['id'] for r in self.baseline['blacklist']}
            new=[r for r in current['blacklist'] if r['id'] not in old]
            if any(r.get('runId')!=self.manifest['id'] or r.get('requestId') not in allowed_request_ids for r in new):
                raise RuntimeError('BLACKLIST_OWNERSHIP_UNCERTAIN')
            ids=[r['id'] for r in new]
        for bid in ids:
            status = await self.page.evaluate('''async (id) => {
              const c=await fetch('/api/v1/auth/csrf',{credentials:'include',cache:'no-store'});
              if(!c.ok) return c.status;
              const t=await c.json();
              if(!t.headerName||!t.token) return 0;
              const r=await fetch('/api/v1/blacklist/'+id,{method:'DELETE',credentials:'include',headers:{[t.headerName]:t.token}});
              return r.status;
            }''', bid)
            if status != 204:
                raise RuntimeError('TEST_BLACKLIST_DELETE_FAILED')
        current = await self.inspect('cleanup-after')
        if {r['id'] for r in current['blacklist']} != {r['id'] for r in self.baseline['blacklist']}:
            raise RuntimeError('BLACKLIST_BASELINE_NOT_RESTORED')
        self.cleanup_ok = True

    async def execute(self):
        from playwright.async_api import async_playwright
        self.session.start()
        await self.sample('preflight-resource', reset=True)
        await self.recalibrate('clock-before')
        self.baseline = await self.inspect('baseline')
        if not self.baseline['nginx_test_ok'] or self.baseline['waf']['health']!='healthy':
            raise RuntimeError('WAF_BASELINE_NOT_HEALTHY')
        self.desired = with_generator(self.baseline['exclusions'], self.baseline['source_ipv4'])
        self.private_state()
        first = await self.send(1)
        deadline = time.monotonic()+45
        while time.monotonic()<deadline:
            state = await self.inspect('https-source', request_id=first['requestId'])
            if state['https_source']['rows']:
                break
            await asyncio.sleep(3)
        if state['https_source'] != dict(rows=1,matches=1):
            raise RuntimeError('HTTPS_SOURCE_NOT_MATCHED')
        self.checks['https_source_matches_ssh'] = True
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(channel='chrome',headless=False)
            self.manifest['browser_version'] = browser.version
            monitor = asyncio.create_task(self.monitor())
            try:
                context = await browser.new_context(viewport=dict(width=1440,height=1000))
                await context.expose_binding('__dgBinding',self.binding)
                await context.add_init_script(path=str(HERE/'browser_trace.js'))
                self.page = await context.new_page()
                await self.page.goto(select_environment('ec2').dashboard_url,timeout=30000)
                print('P7_LOGIN_REQUIRED: 열린 EC2 관리자 Chrome에 직접 로그인해주세요. 비밀번호는 저장하지 않습니다.',flush=True)
                await self.page.wait_for_function('window.__dgReady === true',timeout=600000)
                await asyncio.sleep(1)
                self.check_monitor()
                if not self.ready: raise RuntimeError('STOMP_NOT_OBSERVED')
                self.checks['manual_login_stomp'] = True
                await self.reconfigure(self.desired,'exclude')
                await self.recalibrate('clock-after-login')
                before = await self.collect('pipeline-before')
                self.keys = partition_keys(before['lag'])
                if not zero_lag(before['lag'], self.keys): raise RuntimeError('INITIAL_LAG_NOT_ZERO')
                await self.send(2)
                await asyncio.sleep(1)
                await self.send(3)
                await asyncio.sleep(1)
                await self.send(4,probe=True)
                deadline = time.monotonic()+120
                i = 0
                while time.monotonic()<deadline:
                    i += 1
                    result = await self.collect(f'pipeline-{i:02d}')
                    self.checks.update(connection_checks(self.clients,self.database,self.traces,self.events))
                    self.checks['final_lag_zero'] = zero_lag(result['lag'], self.keys)
                    status = await self.sync_status()
                    self.checks['generator_exclusion_reported'] = status.get('generatorExcluded') is True and status.get('generatorReason')=='CONFIGURED_EXCLUSION'
                    self.checks['fresh_applied_report'] = status.get('status')=='APPLIED' and status.get('stale') is False and status.get('versionsMatch') is True
                    self.persist()
                    if all(self.checks.values()): break
                    await asyncio.sleep(5)
                row = next((r for r in self.database if r['requestId']==self.probe_id),None)
                threats = [t['threatId'] for t in self.traces if t['requestId']==self.probe_id and t.get('threatId')]
                if row and threats:
                    self.manifest['stage'] = 'representative_table'
                    await observe_threat_row(self.page,min(threats),row['logId'])
                    self.checks['representative_table'] = True
                else:
                    self.checks['representative_table'] = False
                self.manifest['connection_verdict'] = 'PASS' if all(self.checks.values()) else 'INCONCLUSIVE'
            finally:
                self.stop_monitor = True
                await asyncio.gather(monitor,return_exceptions=True)
                try:
                    await self.cleanup()
                    if self.changed:
                        current = await self.inspect('restore-precheck')
                        if current['exclusions'] not in (self.desired,self.baseline['exclusions']):
                            raise RuntimeError('EXTERNAL_EXCLUSION_CHANGE_REQUIRES_REVIEW')
                        await self.reconfigure(self.baseline['exclusions'],'restore')
                    await self.recalibrate('clock-recovery')
                    await self.send(999,recovery=True)
                    status = await self.sync_status()
                    deadline = time.monotonic()+45
                    while (status.get('stale') is not False or status.get('status')!='APPLIED') and time.monotonic()<deadline:
                        await asyncio.sleep(5)
                        status = await self.sync_status()
                    self.restored = (self.current['exclusions']==self.baseline['exclusions'] and
                        status.get('status')=='APPLIED' and status.get('stale') is False)
                    if not self.restored:
                        self.manifest['connection_verdict'] = 'INCONCLUSIVE'
                    self.private_state()
                except Exception as error:
                    self.errors.append('복구 확인 실패: '+str(error) if type(error) is RuntimeError else '복구 확인 실패: '+type(error).__name__)
                    self.manifest['connection_verdict'] = 'INCONCLUSIVE'
                    self.private_state()
                await browser.close()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--dry-run',action='store_true')
    modes.add_argument('--execute-check',action='store_true')
    p.add_argument('--ssh-host')
    p.add_argument('--identity-file',type=Path)
    p.add_argument('--host-key-alias')
    p.add_argument('--round',type=int,default=1)
    a = p.parse_args(argv)
    if not 1<=a.round<=99: p.error('회차는 1~99입니다.')
    rid = datetime.now(KST).strftime('%Y%m%dT%H%M%S%z')+f'-ec2-connection-r{a.round:02d}'
    m = dict(id=rid,schema='ec2-connection-check-v1',environment='ec2',planned_at=now(),
        state='PLANNED',connection_verdict='NOT_EVALUATED',performance_verdict='NOT_EVALUATED',
        max_requests=5,max_probe_requests=1,load_generated=False)
    if a.dry_run:
        print(json.dumps(m,ensure_ascii=False,indent=2))
        return 0
    if not a.ssh_host or not a.identity_file or not a.identity_file.is_file(): p.error('기존 SSH 호스트와 키 파일을 확인하세요.')
    settings = SSHSettings(a.ssh_host,a.identity_file,a.host_key_alias)
    output,path = reserve(ROOT,rid,'ec2')
    m.update(local_git_state(),started_at=now(),state='RUNNING')
    m['source_sha256'] = {name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
        ('run_ec2_connection.py','ec2_connection.py','ec2_connection_worker.py','ec2_watch.py',
         'ec2_collection_worker.py','e2e_remote.py','browser_trace.js','fixtures/juiceshop-login.json')}
    run = ConnectionRun(settings,output,path,m)
    run.persist()
    try:
        asyncio.run(run.execute())
        m['state'] = 'COMPLETED'
    except KeyboardInterrupt:
        m.update(state='INTERRUPTED',connection_verdict='INCONCLUSIVE')
    except Exception as error:
        m.update(state='FAILED',connection_verdict='INCONCLUSIVE')
        # 인증·브라우저 예외의 원문은 URL·입력값을 포함할 수 있어 타입만 기록한다.
        run.errors.append('실행 중단: '+(str(error) if type(error) is RuntimeError else type(error).__name__))
    finally:
        run.session.close()
        m['ended_at'] = now()
        run.persist()
    print('연결: '+m['connection_verdict'])
    print('복구 확인: '+str(run.restored))
    print('보고서: '+str(path))
    return 0 if m['connection_verdict']=='PASS' and run.restored else 1


if __name__=='__main__':
    raise SystemExit(main())
