"""AI·WAF E2E 실행기. local 실행과 EC2 계획 확인을 환경별로 분리한다."""
import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
import ssl
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

from e2e_core import SPEC, FIXTURE, fixture, client_record, parse_points, parse_traces, browser_record, database_sql, parse_database, evaluate, ClockObservationError
from e2e_environment import select_environment, result_paths
from guard import AutoStopGuard, PointReader, stop_load
from load_policy import load_policy
from metrics import parse_lag, resource_peaks
from pipeline import partition_keys, zero_lag, lag_complete, lag_maxima
from run_experiment import command, reserve, save, format_record_time, now, KST, ROOT, HERE


class ResponseObservationError(ValueError):
    def __init__(self, status):
        self.status = status
        super().__init__('WAF 응답 계측 정보 미확인')


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--environment', choices=('local', 'ec2'), default='local')
    p.add_argument('--target-url', help='환경별 허용 목록의 JuiceShop root URL')
    p.add_argument('--dashboard-url', help='환경별 허용 목록의 관리자 화면 root URL')
    p.add_argument('--rate', type=int, choices=(1, 3, 5), default=1)
    p.add_argument('--round', type=int, default=1)
    p.add_argument('--channel', choices=('chrome', 'msedge', 'chromium'), default='chrome')
    p.add_argument('--fixture', type=Path, default=FIXTURE)
    p.add_argument('--connection-check', action='store_true', help='1회/초, 워밍업 10초·측정 10초의 연결 검증. 본 실험과 분리')
    p.add_argument('--confirm-ip-policy', action='store_true', help='발생기 IP의 차단 제외·등록 정책을 확인했음')
    p.add_argument('--login-timeout', type=int, default=180)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--execute', action='store_true')
    a = p.parse_args(argv)
    if a.round < 1 or not 30 <= a.login_timeout <= 600 or (a.connection_check and a.rate != 1):
        p.error('회차는 양수, 로그인 대기는 30~600초, 연결 검증은 rate=1이어야 합니다.')
    if a.execute and not a.confirm_ip_policy:
        p.error('실제 실행에는 --confirm-ip-policy가 필요합니다. 실행기가 차단 정책을 변경하지 않습니다.')
    try:
        a.runtime_environment = select_environment(a.environment, a.target_url, a.dashboard_url)
        if a.execute:
            a.runtime_environment.require_execution_ready()
    except ValueError as error:
        p.error(str(error))
    return a


def build_request(phase, sequence, run_id, probe, *, kind='probe', environment=None):
    environment = environment or select_environment()
    # 응답 본문·Set-Cookie·인증 결과 토큰을 읽거나 보존하지 않는다.
    headers = dict(probe['headers'])
    headers.update({'X-DualGuard-Test-Run': run_id, 'X-DualGuard-Test-Phase': phase,
                    'X-DualGuard-Test-Kind': kind, 'X-DualGuard-Test-Seq': str(sequence)})
    # Windows localhost의 IPv6 연결 재시도 지연을 제외한다. HTTP Host는 유지한다.
    if environment.name == 'local':
        headers['Host'] = 'localhost'
    data = json.dumps(probe['body']).encode() if kind == 'probe' else None
    return urllib.request.Request(environment.probe_url(probe['path'] if kind == 'probe' else '/'),
                                  data=data, headers=headers, method='POST' if kind == 'probe' else 'GET')


def request_opener(environment):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
    if environment.name == 'ec2':
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return urllib.request.build_opener(*handlers)


def request(phase, sequence, run_id, probe, *, kind='probe', environment=None, clock=None):
    environment = environment or select_environment()
    environment.require_execution_ready()
    req = build_request(phase, sequence, run_id, probe, kind=kind, environment=environment)
    opener = request_opener(environment)
    c0, sent = time.perf_counter(), time.time() * 1000
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        # 로그인 응답의 토큰을 저장하지 않고 버린다. 큰 응답은 측정 범위 밖이다.
        if len(response.read(1048577)) > 1048576:
            raise ValueError('응답 크기 제한 초과')
        ended = time.time() * 1000
        try:
            return client_record(phase, kind, sequence, dict(response.headers), response.code,
                                 (time.perf_counter() - c0) * 1000, sent, ended, c0,clock=clock)
        except ValueError as error:
            raise ResponseObservationError(response.code) from error


def report(manifest, metrics, output):
    lines = [f"# 실험 기록: {format_record_time(manifest['planned_at']).split()[0]} — AI·WAF E2E v2",
             '', '## 실행 정보', f"- ID: {manifest['id']}", f"- 실행 상태: {manifest['state']}",
             f"- 판정: {metrics.get('verdict', 'NOT_EVALUATED')}",
             f"- 환경: {manifest.get('environment', 'local')}",
             f"- 구분: {'소량 연결 검증' if manifest['connection_check'] else '기준 측정 한 회차'}",
             f"- 시작 / 종료: {format_record_time(manifest.get('started_at'))} / {format_record_time(manifest.get('ended_at'))}",
             f"- 원본: {output.as_posix()}", '', '## S — Situation',
             '두 분기의 저장·알림 처리와 실제 브라우저 수신·표시를 분리해 관측한다.', '', '## T — Task',
             '동일 요청을 서버 requestId·alertId에 연결하고 출처별 완료·지연을 대조한다.', '', '## T — Target',
             f"- 요청률: {manifest['rate']}/초, 측정 {manifest['seconds']}초, 워밍업 {manifest['warmup_seconds']}초 제외.",
             '- 실행 전 저장한 measurement-contract.json과 manifest.json의 목표·fixture·해시를 따른다.',
             '- p50·p99는 참고값. 한 회차 PASS를 3회 단계 PASS로 표현하지 않는다.', '', '## A — Action',
             '- client-requests·pipeline-events·browser-events·progress JSONL을 수집한다.',
             '- 앱·DB·차단 정책 자동 변경 없음. 관리자 세션은 메모리에서만 사용.', '', '## R — Result',
             '| 구간 | 표본 수 | 평균 ms | p50 ms | p95 ms | p99 ms | 최대 ms | 미확인 |',
             '| --- | --- | --- | --- | --- | --- | --- | --- |']
    def display(v):
        return '미측정' if v is None else str(round(v, 3))
    for key, stats in metrics.get('stats_ms', {}).items():
        lines.append('| ' + ' | '.join([key, str(stats['count'])] +
            [display(stats[k]) for k in ('avg_ms', 'p50_ms', 'p95_ms', 'p99_ms', 'max_ms')] +
            [str(metrics.get('missing', {}).get(key, 0))]) + ' |')
    lines += ['', '- 정합성: ' + json.dumps(metrics.get('counts', {}), ensure_ascii=False)]
    lines += ['- ' + r for r in metrics.get('reasons', [])]
    lines += ['', '## T — Trouble', '- 사건·중단 근거: events.jsonl, guard-summary.json',
              '- WAF 시작 시각은 msec−request_time으로 산출한 밀리초 단위 관측값이다.',
              '- 커밋 시각은 커밋 후 콜백 시각이다. 브라우저 지연에는 관측기 전달 비용이 포함된다.',
              ('- DB DATETIME은 지연 계산에 사용하지 않는다. 탐지 정확도·EC2 성능은 평가 범위 밖이다.'
               if manifest.get('environment', 'local') == 'local' else
               '- DB DATETIME은 지연 계산에 사용하지 않는다. PC HTTP·브라우저 지연과 EC2 서버 내부 지연을 구분한다.'),
              '- 복구: 서비스 중단 없음. 종료 시 소유한 k6·자동화 브라우저만 정리한다.']
    return '\n'.join(lines) + '\n'


class Experiment:
    def __init__(self, args, spec, probe, manifest, output, report_path, *, ec2_contract=None):
        self.args, self.spec, self.probe, self.manifest = args, spec, probe, manifest
        self.output, self.report_path = output, report_path
        self.environment = getattr(args, 'runtime_environment', None) or select_environment()
        if self.environment.name=='ec2' and ec2_contract is not None:
            from ec2_load_policy import validate_contract
            validate_contract(ec2_contract)
        else:
            self.environment.require_execution_ready()
        # EC2 실제 실행은 P5~P8 준비 전 계속 차단한다. P4는 수집 전용 CLI로 검증한다.
        self.remote_collector = getattr(args, 'remote_collector', None)
        self.clock_calibration = getattr(args, 'clock_calibration', None)
        self.ec2_guard = getattr(args, 'ec2_guard', None)
        # 호출자는 자격 증명을 메모리에만 보관한 수집 함수를 제공한다.
        self.db_observer = getattr(args, 'db_observer', None)
        self.db_baseline = None
        self.compose = ['docker', 'compose', '--env-file', '.env', '-f', 'compose.yaml']
        self.clients, self.browser_events, self.traces, self.database, self.errors = [], [], [], [], []
        self.trace_keys, self.points_readers, self.seen_clients = set(), [], set()
        self.resources, self.snapshots = [], []
        self.ready, self.heartbeat, self.done = False, 0, False
        self.guard = None
        self.process = None
        self.page = None
        self.keys = set()
        self.elapsed = None
        self.final_lag = False
        self.phase_name = 'preflight'
        self.previous_counts, self.previous_progress_at = {}, None

    def append(self, filename, item):
        with (self.output / filename).open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(item, ensure_ascii=False) + '\n')

    def event(self, kind, message):
        self.append('events.jsonl', dict(at=now(), kind=kind, message=message))

    def add_client(self, row):
        key = (row['phase'], row['kind'], row['sequence'])
        if key in self.seen_clients:
            raise ValueError('클라이언트 요청 순번 중복')
        self.seen_clients.add(key)
        self.clients.append(row)
        self.append('client-requests.jsonl', row)

    async def cmd(self, args, timeout=15, input_text=None):
        result = await asyncio.to_thread(command, args, timeout, input_text)
        if result['code']:
            raise RuntimeError('외부 조회 실패: ' + args[0])
        return result['stdout']

    def record_remote_collection(self, value):
        self.append('collection-commands.jsonl', dict(at=now(), transport=value['transport'],
            commands=value['commands'], status=value['collection_status'], errors=value['errors']))
        if value['collection_status'] != 'COLLECTED':
            raise RuntimeError('원격 수집 불완전: ' + ','.join(value['errors']))

    def should_collect_lag(self):
        """이번 pipeline 수집에 Kafka lag 조회를 포함할지. 로컬·기본은 항상 포함한다."""
        return True

    async def pipeline_inputs(self):
        if self.environment.name == 'ec2':
            if self.remote_collector is None:
                raise RuntimeError('원격 수집 어댑터 설정이 필요합니다.')
            value = await asyncio.to_thread(self.remote_collector.collect, self.manifest['id'],
                self.manifest['started_at'], {c['requestId'] for c in self.clients},
                mode='pipeline', expected_keys=self.keys, include_lag=self.should_collect_lag())
            self.record_remote_collection(value)
            return value['lag'], value['database'], value['traces']
        started = now()
        lag_text = await self.cmd(self.compose + ['exec', '-T', 'kafka', 'kafka-consumer-groups',
            '--bootstrap-server', 'kafka:29092', '--all-groups', '--describe'])
        snap = dict(at=now(), started_at=started, code=0, rows=parse_lag(lag_text))
        db_text = await self.cmd(self.compose + ['exec', '-T', 'db', 'sh', '-c',
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -u root -D security_db '
            '--default-character-set=utf8mb4 --batch --raw --skip-column-names'],
            input_text=database_sql(self.manifest['id']))
        text = await self.cmd(self.compose + ['logs', '--no-color', '--since', self.manifest['started_at'],
                                            '--tail', '20000', 'backend'])
        if 'DG_TRACE_UNAVAILABLE' in text or 'DG_TRACE_WRITE_FAILED' in text:
            raise RuntimeError('백엔드 계측 실패 기록 발견')
        return snap, parse_database(db_text), parse_traces(text)

    async def collect(self):
        started = now()
        snap, self.database, traces = await self.pipeline_inputs()
        # snap이 None이면 이번 수집에서 lag 조회를 의도적으로 생략한 것이다(EC2 부하 중 주기 분리).
        if snap is not None:
            if not self.keys:
                self.keys = partition_keys(snap)
            if not lag_complete(snap, self.keys):
                raise RuntimeError('필수 Kafka group·partition 표본 누락')
            self.snapshots.append(snap)
            self.guard.collected('kafka_lag', True)
        save(self.output / 'database.json', self.database)
        if self.page:
            policies = {r['alertId']: ['AI', 'WAF'] if r['kind'] == 'probe' else
                        [s for s, k in [('AI', 'aiDetected'), ('WAF', 'wafDetected')] if r.get(k)]
                        for r in self.database if r.get('alertId')}
            await self.page.evaluate('(policy) => {window.__dgAlertPolicy = policy;}', policies)
        known = {c['requestId'] for c in self.clients}
        for trace in traces:
            if trace['requestId'] not in known:
                continue
            key = json.dumps(trace, sort_keys=True)
            if key not in self.trace_keys:
                self.trace_keys.add(key)
                self.traces.append(trace)
                self.append('pipeline-events.jsonl', trace)
        counts = {}
        observed = time.perf_counter()
        for phase in ('warmup', 'measurement'):
            phase_ids = {c['requestId'] for c in self.clients if c['phase'] == phase}
            counts[phase] = {stage: len({t['requestId'] for t in self.traces
                if t['stage'] == stage and t['requestId'] in phase_ids})
                for stage in ('LOG_COMMITTED', 'AI_RESULT_COMMITTED', 'WAF_COMMITTED')}
            counts[phase]['http'] = len(phase_ids)
            counts[phase]['pending_ai'] = len(phase_ids) - counts[phase]['AI_RESULT_COMMITTED']
            old = self.previous_counts.get(phase)
            counts[phase]['ai_completed_per_second'] = (
                (counts[phase]['AI_RESULT_COMMITTED'] - old['AI_RESULT_COMMITTED'])
                / (observed - self.previous_progress_at)
                if old is not None and observed > self.previous_progress_at else None)
            counts[phase]['logs_committed_per_second'] = (
                (counts[phase]['LOG_COMMITTED']-old['LOG_COMMITTED'])/(observed-self.previous_progress_at)
                if old is not None and observed>self.previous_progress_at else None)
            alerts = {r.get('alertId') for r in self.database if r['phase'] == phase}
            for source in ('AI', 'WAF'):
                counts[phase]['browser_' + source] = len({b.get('alertId') for b in self.browser_events
                    if b['kind'] == 'received' and source in b.get('sources', []) and b.get('alertId') in alerts})
        self.append('progress.jsonl', dict(at=now(), started_at=started, lag=snap, counts=counts,
            browser_sources_all_observed={s: len({b.get('alertId') for b in self.browser_events
                if b['kind'] == 'received' and s in b.get('sources', [])}) for s in ('AI', 'WAF')}))
        self.previous_counts, self.previous_progress_at = counts, observed
        self.guard.collected('pipeline', True)
        return snap

    async def sampler(self):
        while not self.done:
            try:
                await self.collect()
            except Exception as error:
                self.guard.collected('pipeline', False)
                self.errors.append('업무 계측 실패: ' + type(error).__name__)
                self.event('error', self.errors[-1])
            await asyncio.sleep(10)

    async def monitor(self):
        while not self.done:
            try:
                if self.environment.name == 'ec2':
                    if self.ec2_guard is None:
                        raise RuntimeError('EC2 자원 감시가 필요합니다.')
                    await asyncio.to_thread(self.ec2_guard.resources)
                    self.check_abort()
                else:
                    await asyncio.to_thread(self.guard.resources)
                value = await self.resource_input()
                self.resources.append(value)
                self.append('docker-stats.jsonl', value)
                self.guard.collected('docker_stats', True)
                healthy = self.ready and time.perf_counter() - self.heartbeat < 5
                self.guard.collected('browser', healthy)
            except Exception:
                self.guard.collected('resources', False)
            await asyncio.sleep(5)

    async def resource_input(self):
        if self.environment.name == 'ec2':
            if self.remote_collector is None:
                raise RuntimeError('원격 수집 어댑터 설정이 필요합니다.')
            value = await asyncio.to_thread(self.remote_collector.collect, self.manifest['id'],
                self.manifest['started_at'], mode='resources')
            self.record_remote_collection(value)
            return value['resources']
        text = await self.cmd(['docker', 'stats', '--no-stream', '--format', 'json', *self.ids], timeout=10)
        containers = [json.loads(line) for line in text.splitlines() if line.strip()]
        if not containers:
            raise ValueError('자원 표본 없음')
        return dict(at=now(), containers=[{k: c.get(k) for k in ('Name', 'CPUPerc', 'MemPerc')} for c in containers])

    async def database_observation(self, label):
        if self.environment.name != 'ec2':
            return None
        if self.db_observer is None:
            raise RuntimeError('EC2 DB 관측 제공자가 필요합니다.')
        value = await asyncio.to_thread(self.db_observer, self.manifest['id'])
        save(self.output / ('db-observation-' + label + '.json'), value)
        if value['collection_status'] != 'COLLECTED':
            raise RuntimeError('EC2 DB 관측 불완전')
        if label == 'before':
            self.db_baseline = value
        elif label == 'after':
            from ec2_db import compare
            comparison = compare(self.db_baseline, value)
            save(self.output / 'db-observation-comparison.json', comparison)
            if comparison['comparison_status'] != 'COMPARABLE':
                raise RuntimeError('EC2 DB 계수 초기화·수집 불완전 확인 필요')
        return value

    def binding(self, source, value):
        # 계측 브라우저의 주 프레임만 받는다. 자격 증명·IP·본문은 화이트리스트에서 제거한다.
        if source['frame'] != self.page.main_frame:
            return
        try:
            event = browser_record(value, time.perf_counter())
            if event['kind'] == 'heartbeat':
                self.heartbeat = event['observed']
                return
            if event['kind'] in {'ready', 'disconnected'}:
                self.ready = event['kind'] == 'ready'
                self.heartbeat = event['observed']
            self.browser_events.append(event)
            self.append('browser-events.jsonl', event)
        except Exception:
            if self.guard:
                self.guard.collected('browser_event', False)

    def check_abort(self):
        if self.ec2_guard is not None:
            self.ec2_guard.watchdog()
            if self.ec2_guard.abort:
                raise RuntimeError('자동 중단: ' + self.ec2_guard.abort['code'])
        if self.guard.abort:
            raise RuntimeError('자동 중단: ' + self.guard.abort['code'])

    async def refresh_clock_observation(self):
        # 로컬 실행에서는 기존 검증·중단 동작을 유지한다.
        return False

    async def read_client_points(self, points, *, partial=False):
        try:
            return parse_points(points, partial=partial, clock=self.clock_calibration)
        except ClockObservationError:
            if not await self.refresh_clock_observation():
                raise
            return parse_points(points, partial=partial, clock=self.clock_calibration)

    async def phase(self, phase, seconds, rate):
        self.phase_name = phase
        directory = self.output / 'raw'
        points = directory / (phase + '-points.jsonl')
        summary = directory / (phase + '-summary.json')
        env = dict(os.environ, K6_NO_USAGE_REPORT='true', RUN_RATE=str(rate), RUN_SECONDS=str(seconds),
            RUN_PHASE=phase, RUN_ID=self.manifest['id'], TARGET_URL=self.environment.target_url,
            DG_ENVIRONMENT=self.environment.name, K6_INSECURE_SKIP_TLS_VERIFY='false',
            PROBE_USER_AGENT=self.probe['headers'].get('User-Agent', ''), SUMMARY_PATH=str(summary))
        if self.environment.name=='ec2':
            env['DG_EC2_CONTRACT_SHA256']=self.manifest['contract_sha256']
        args = ['k6', 'run', '--no-color', '--out', 'json=' + str(points), str(HERE / 'e2e_background.js')]
        reader = PointReader(points)
        self.points_readers.append(reader)
        clock = time.perf_counter()
        self.event('phase_start', phase)
        with (directory / (phase + '-k6.log')).open('w', encoding='utf-8') as log:
            options = dict(cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            if os.name == 'nt':
                options['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
            self.process = subprocess.Popen(args, **options)
            if self.ec2_guard is not None:
                self.ec2_guard.attach_owned_load(self.process)
            async def probes():
                for sequence in range((seconds + 9) // 10):
                    target = clock + sequence * 10
                    await asyncio.sleep(max(0, target - time.perf_counter()))
                    self.check_abort()
                    try:
                        row = await self.send_probe(phase,sequence)
                    except ResponseObservationError as error:
                        if error.status != 200:
                            self.guard.rules.trip('probe_http_status', 'probe HTTP 상태 위반', 'FAIL', {'status': error.status})
                        raise
                    except (urllib.error.URLError, TimeoutError):
                        self.guard.rules.trip('probe_transport', 'probe HTTP 요청 실패', 'FAIL', {})
                        raise
                    self.add_client(row)
                    self.guard.rules.http(dict(at=datetime.fromtimestamp(row['ended_ms']/1000, timezone.utc).isoformat(),
                                               status=row['status'], duration_ms=row['duration_ms']))
            task = asyncio.create_task(probes())
            try:
                while self.process.poll() is None:
                    self.check_abort()
                    if time.perf_counter() - clock > seconds + 30:
                        raise RuntimeError('k6 실행 시간 초과')
                    if points.exists():
                        for point in reader.read():
                            self.guard.rules.http(point)
                        for row in await self.read_client_points(points, partial=True):
                            if (row['phase'], row['kind'], row['sequence']) not in self.seen_clients:
                                self.add_client(row)
                    if task.done() and task.exception():
                        raise task.exception()
                    await asyncio.sleep(.1)
                await task
                if self.process.returncode:
                    self.guard.rules.trip('k6_failed', 'k6 임계값·실행 실패', 'INCONCLUSIVE' if self.environment.name=='ec2' else 'FAIL', {})
                for point in reader.read():
                    self.guard.rules.http(point)
                if reader.failed or reader.buffer:
                    raise RuntimeError('k6 부분·손상 표본')
                for row in await self.read_client_points(points):
                    if (row['phase'], row['kind'], row['sequence']) not in self.seen_clients:
                        self.add_client(row)
                data = json.loads(summary.read_text(encoding='utf-8'))
                metrics = data.get('metrics', data.get('results', {}).get('metrics', {}))
                if isinstance(metrics, list):
                    metrics = {m['name']: m for m in metrics}
                dropped = metrics.get('dropped_iterations', {}).get('values', {}).get('count')
                http_count = metrics.get('http_reqs', {}).get('values', {}).get('count')
                actual = len([c for c in self.clients if c['phase'] == phase and c['kind'] == 'background'
                              and c['sequence'] != 999999])
                if dropped is None or http_count != actual:
                    raise RuntimeError('k6 summary·개별 요청 표본 대조 실패')
                if dropped:
                    self.guard.rules.trip('dropped_iterations', '미전송 반복 발생', 'INCONCLUSIVE' if self.environment.name=='ec2' else 'FAIL', {'count': dropped})
                elapsed = time.perf_counter() - clock
                if elapsed < seconds:
                    raise RuntimeError('실제 부하 기간 미충족')
                return elapsed
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await asyncio.to_thread(stop_load, self.process)

    async def send_probe(self,phase,sequence):
        return await asyncio.to_thread(request,phase,sequence,self.manifest['id'],self.probe,
            environment=self.environment,clock=self.clock_calibration)

    async def drain(self):
        deadline, zeros = time.perf_counter() + 60, 0
        while time.perf_counter() <= deadline:
            self.check_abort()
            snap = await self.collect()
            ids = {c['requestId'] for c in self.clients}
            completed = {t['requestId'] for t in self.traces if t['stage'] == 'AI_RESULT_COMMITTED'}
            probe_ids = {c['requestId'] for c in self.clients if c['kind'] == 'probe'}
            probe_alerts = {r['requestId']: r.get('alertId') for r in self.database}
            seen = {(e.get('alertId'), s) for e in self.browser_events if e['kind'] == 'dom' for s in e.get('sources', [])}
            visible = all((probe_alerts.get(r), s) in seen for r in probe_ids for s in ('AI', 'WAF'))
            zeros = zeros + 1 if zero_lag(snap, self.keys) and ids <= completed and visible else 0
            if zeros >= 2:
                return True
            await asyncio.sleep(10)
        return False

    async def execute(self):
        from playwright.async_api import async_playwright
        from importlib.metadata import version
        self.manifest.update(state='RUNNING', started_at=now())
        self.manifest['versions'] = dict(python=sys.version.split()[0],
            playwright=version('playwright'),
            k6=(await self.cmd(['k6', 'version'])).strip(),
            docker=(await self.cmd(['docker', '--version'])).strip())
        self.ids = (await self.cmd(self.compose + ['ps', '-q'])).split()
        if not self.ids:
            raise RuntimeError('실행 중인 Compose 컨테이너 없음')
        policy, _ = load_policy()
        self.guard = AutoStopGuard(policy, self.output, self.compose, self.ids, command, self.event)
        await asyncio.to_thread(self.guard.preflight)
        enabled = (await self.cmd(self.compose + ['exec', '-T', 'backend', 'printenv', 'PIPELINE_TRACE_ENABLED'])).strip()
        if enabled.lower() != 'true':
            raise RuntimeError('백엔드 계측이 비활성화됨')
        audit = await self.cmd(self.compose + ['exec', '-T', 'db', 'sh', '-c',
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -u root -D security_db --batch --skip-column-names'],
            input_text="""SELECT CONCAT(TABLE_NAME,':',GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX))
FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='security_db' AND NON_UNIQUE=0
AND TABLE_NAME IN ('network_logs','waf_detections','request_alerts') GROUP BY TABLE_NAME,INDEX_NAME;""")
        required = {'network_logs:request_id', 'waf_detections:request_id', 'waf_detections:threat_id',
                    'request_alerts:alert_key', 'request_alerts:alert_id'}
        if not required <= set(audit.splitlines()):
            raise RuntimeError('필수 DB UNIQUE 제약 확인 필요')
        self.manifest['unique_indexes'] = sorted(set(audit.splitlines()))
        self.manifest['db_start_counts'] = (await self.cmd(self.compose + ['exec', '-T', 'db', 'sh', '-c',
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -u root -D security_db --batch --skip-column-names'],
            input_text='SELECT (SELECT COUNT(*) FROM network_logs),(SELECT COUNT(*) FROM detected_threats);')).strip()
        self.manifest['images'] = (await self.cmd(['docker', 'inspect', '--format',
            '{{.Id}} {{.Config.Image}} {{.Image}}', *self.ids])).splitlines()
        self.manifest['runner_sha'] = (await self.cmd(['git', 'rev-parse', 'HEAD'])).strip()
        self.manifest['changed_files'] = (await self.cmd(['git', 'status', '--short'])).splitlines()
        async with async_playwright() as pw:
            options = dict(headless=False)
            if self.args.channel != 'chromium':
                options['channel'] = self.args.channel
            browser = await pw.chromium.launch(**options)
            self.manifest['versions']['browser'] = browser.version
            try:
                context = await browser.new_context(viewport=dict(width=1440, height=1000))
                await context.expose_binding('__dgBinding', self.binding)
                await context.add_init_script(path=str(HERE / 'browser_trace.js'))
                self.page = await context.new_page()
                def api_finished(req):
                    from urllib.parse import urlsplit
                    path = urlsplit(req.url).path
                    if path in {'/api/v1/logs', '/api/v1/threats/grouped', '/api/v1/blacklist', '/api/v1/waf/sync-status'}:
                        duration = req.timing.get('responseEnd', -1)
                        if duration >= 0:
                            self.append('dashboard-api.jsonl', dict(at=now(), phase=self.phase_name,
                                                                  endpoint=path, duration_ms=duration))
                self.page.on('requestfinished', api_finished)
                await self.page.goto(self.environment.dashboard_url, timeout=30000)
                print('열린 자동화 브라우저에서 관리자 로그인 후 대시보드를 유지해주세요. 비밀번호·쿠키는 저장하지 않습니다.', flush=True)
                await self.page.wait_for_function('window.__dgReady === true', timeout=self.args.login_timeout*1000)
                # 최초 ready 이후 binding이 Python에 도착할 시간을 준다.
                await asyncio.sleep(1)
                if not self.ready:
                    raise RuntimeError('실제 프론트 계측 연결 미확인')
                before = await self.collect()
                if not zero_lag(before, self.keys) or self.database:
                    raise RuntimeError('초기 Kafka 적체·실험 ID 중복 확인 필요')
                calibration = await asyncio.to_thread(request, 'warmup', 999999, self.manifest['id'], self.probe,
                                                     kind='background', environment=self.environment)
                self.add_client(calibration)
                self.manifest['clock_check'] = dict(rtt_ms=calibration['ended_ms']-calibration['sent_ms'],
                    ingress=calibration['ingress'], sent_ms=calibration['sent_ms'], ended_ms=calibration['ended_ms'],
                    resolution_ms=1, method='nginx_msec_minus_request_time', accepted_error_bound_ms=100)
                if calibration['status'] != 200 or self.manifest['clock_check']['rtt_ms'] > 100:
                    raise RuntimeError('저부하 시계 교차 검증 조건 미충족: '
                        f"HTTP {calibration['status']}, 왕복 {self.manifest['clock_check']['rtt_ms']:.3f}ms "
                        '(기준 HTTP 200 및 100ms 이내)')
                tasks = [asyncio.create_task(self.monitor())]
                try:
                    await self.phase('warmup', self.manifest['warmup_seconds'], 1)
                    if not await self.drain():
                        raise RuntimeError('워밍업의 저장·AI·브라우저·lag 정리 미확인')
                    # 확인을 마친 알림만 닫아 본 측정 화면 조건을 고정한다.
                    await self.page.locator('[id^="request-alert-"] button[aria-label="close"]').evaluate_all('(nodes) => nodes.forEach(n => n.click())')
                    await self.database_observation('before')
                    tasks.append(asyncio.create_task(self.sampler()))
                    self.elapsed = await self.phase('measurement', self.manifest['seconds'], self.args.rate)
                    # 수집 경쟁을 피하고 최종 관측은 최소 간격을 둔 단일 루프에서 수행한다.
                    tasks[-1].cancel()
                    await asyncio.gather(tasks.pop(), return_exceptions=True)
                    self.final_lag = await self.drain()
                    self.check_abort()
                    await self.database_observation('after')
                    await self.table_check()
                    self.manifest['state'] = 'COMPLETED'
                finally:
                    self.done = True
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                await browser.close()

    async def table_check(self):
        probe_ids = {c['requestId'] for c in self.clients if c['phase'] == 'measurement' and c['kind'] == 'probe'}
        row = next((r for r in self.database if r['requestId'] in probe_ids and r.get('logId')), None)
        if not row:
            self.errors.append('대표 테이블 표본 없음')
            return
        # 원인 위협 ID가 아닌 실제 연결된 원본 로그 버튼으로 DOM 반영을 확인한다.
        traces = [t for t in self.traces if t['requestId'] == row['requestId'] and t.get('threatId')]
        if not traces:
            self.errors.append('대표 테이블 위협 ID 없음')
            return
        field = self.page.locator('input[name="threatId"]')
        await field.fill(str(min(t['threatId'] for t in traces)))
        await field.locator('xpath=ancestor::form').get_by_role('button', name='검색', exact=True).click()
        table = self.page.get_by_role('region', name='위협 탐지 데이터 표', exact=True)
        await table.get_by_role('button', name=f"원본 로그 {row['logId']} 상세 보기", exact=True).wait_for(state='visible', timeout=10000)
        self.append('browser-events.jsonl', dict(kind='representative_table', requestId=row['requestId'],
                                               logId=row['logId'], observed=time.perf_counter()))


def main(argv=None):
    args = arguments(argv)
    environment = args.runtime_environment
    contract_raw = (SPEC if environment.name == 'local' else environment.contract_path).read_bytes()
    spec = json.loads(contract_raw)
    probe, fixture_hash = fixture(args.fixture)
    if args.connection_check:
        seconds, warmup = 10, 10
    elif environment.name == 'local':
        seconds, warmup = 120, 30
    else:
        seconds, warmup = spec['proposal']['measurement_seconds'], spec['proposal']['warmup_seconds']
    scenario = f'{environment.name}-e2e-check' if args.connection_check else f'{environment.name}-e2e-rps{args.rate}'
    run_id = datetime.now(KST).strftime('%Y%m%dT%H%M%S%z') + f'-{scenario}-r{args.round:02d}'
    manifest = dict(id=run_id, planned_at=now(), state='PLANNED', rate=args.rate, seconds=seconds,
        warmup_seconds=warmup, connection_check=args.connection_check,
        fixture_sha256=fixture_hash, ip_policy_confirmed=args.confirm_ip_policy,
        contract_sha256=hashlib.sha256(contract_raw).hexdigest(), **environment.public_plan())
    output_plan, report_plan = result_paths(ROOT, run_id, environment.name)
    manifest['planned_output'] = output_plan.relative_to(ROOT).as_posix()
    manifest['planned_report'] = report_plan.relative_to(ROOT).as_posix()
    if args.dry_run:
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
        return 0
    output, report_path = reserve(ROOT, run_id)
    (output / 'measurement-contract.json').write_bytes(contract_raw)
    manifest['runner_files_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in HERE.iterdir() if p.is_file() and p.suffix in ('.py', '.js')}
    manifest['app_sources_sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [ROOT/'waf/nginx-logging.conf.template', ROOT/'waf/nginx.conf.template',
                  ROOT/'waf/njs/headers.js', ROOT/'frontend/src/hooks/useWebSocket.js',
                  ROOT/'frontend/src/utils/e2eTrace.js', ROOT/'AI_new/models.lock.json']}
    save(output / 'manifest.json', manifest)
    report_path.write_text(report(manifest, {}, output), encoding='utf-8')
    experiment = Experiment(args, spec, probe, manifest, output, report_path)
    try:
        asyncio.run(experiment.execute())
    except (Exception, KeyboardInterrupt) as error:
        manifest['state'] = 'ABORTED' if experiment.clients else 'BLOCKED'
        # 예외 본문에는 인증 정보가 포함될 수 있으므로 형식만 저장한다.
        detail = str(error) if type(error) is RuntimeError else type(error).__name__
        experiment.errors.append('실행·관측 미완료: ' + detail)
        experiment.event('error', experiment.errors[-1])
    finally:
        if experiment.process and experiment.process.poll() is None:
            stop_load(experiment.process)
        metrics = evaluate(experiment.clients, experiment.traces, experiment.database, experiment.browser_events,
            {**spec, 'workload': {**spec['workload'], 'measurement_seconds': seconds}}, errors=experiment.errors,
            abort=experiment.guard.abort if experiment.guard else None, elapsed=experiment.elapsed,
            final_lag=experiment.final_lag,
            observation_complete=manifest['state'] == 'COMPLETED' and not experiment.errors)
        if manifest['state'] != 'COMPLETED' and metrics['verdict'] == 'PASS':
            metrics.update(verdict='INCONCLUSIVE', reasons=['실행 완료 미확인'])
        manifest['ended_at'] = now()
        metrics['resource_peaks'] = resource_peaks(experiment.resources)
        metrics['lag_maxima'] = lag_maxima(experiment.snapshots)
        metrics['guard'] = experiment.guard.summary() if experiment.guard else None
        if metrics['guard']:
            metrics['guard']['http_stream_complete'] = bool(experiment.points_readers) and all(
                not r.buffer and not r.failed for r in experiment.points_readers)
        metrics['evidence_sha256'] = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in output.rglob('*') if p.is_file() and p.name not in ('manifest.json', 'metrics.json')}
        save(output / 'manifest.json', manifest)
        save(output / 'metrics.json', metrics)
        report_path.write_text(report(manifest, metrics, output), encoding='utf-8')
        print('결과:', metrics['verdict'], '\n보고서:', report_path, '\n원본:', output)
    return 0 if metrics['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
