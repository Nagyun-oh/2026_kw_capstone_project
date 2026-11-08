"""SSH 표준 입력으로 실행하는 읽기 전용 수집기. 서버에 파일을 설치하지 않는다.

단독 CLI가 아니라 e2e_remote.py가 검증한 요청을 main()에 전달한다.
일반 로그·환경 값·DB 본문·명령 stderr는 SSH 응답에 포함하지 않는다.
DB 조회가 실패하면 stderr에서 원인 분류 코드(MySQL 오류 번호/SQLSTATE 또는 고정 표시)만 뽑아 남긴다.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time

SCHEMA = 'dualguard-ec2-collection-v1'
REPO = '/home/ubuntu/2026_kw_capstone_project'
PROJECT = 'security-platform-aws'
SERVICES = {'backend', 'frontend', 'ai', 'db', 'kafka', 'zookeeper', 'waf', 'fluent-bit', 'juiceshop'}
TRACE_KEYS = ('schema', 'stage', 'outcome', 'requestId', 'logId', 'threatId', 'alertId', 'revision', 'sources', 'at')
DB_KEYS = ('requestId', 'logId', 'phase', 'kind', 'sequence', 'ingress', 'alertId',
           'revision', 'aiDetected', 'wafDetected', 'aiRows', 'wafRows')


def now():
    return datetime.now(timezone.utc).isoformat()


MYSQL_ERROR = re.compile(r'ERROR (\d{4}) \(([0-9A-Z]{5})\)')


def error_codes(text):
    """실패한 명령의 stderr에서 원인 분류 코드만 뽑는다. 메시지 본문은 응답에 넣지 않는다."""
    codes = sorted({f'{number}/{state}' for number, state in MYSQL_ERROR.findall(text)})
    if 'Error response from daemon' in text:
        codes.append('DOCKER_DAEMON')
    if text.startswith('sudo:') or '\nsudo:' in text:
        codes.append('SUDO')
    if not codes:
        codes.append('NO_STDERR' if not text.strip() else 'OTHER')
    return codes[:5]


class Runner:
    """Linux 비차단 읽기와 제한 시간. 종료할 수 있는 것은 자신이 시작한 조회 프로세스뿐이다."""
    def __init__(self):
        self.commands = []

    def run(self, label, argv, *, input_text=None, timeout=12, transform=None, max_bytes=4*1024*1024,
            merge_stderr=False, classify_errors=False):
        item = dict(check=label, started_at=now(), timeout_seconds=timeout,
                    status='UNAVAILABLE', exit_code=None, bytes_read=0, lines_read=0)
        started, proc = time.monotonic(), None
        lines, pending = [], b''
        # 실패 원인 분류용 stderr는 이름 없는 임시 파일(생성 즉시 삭제됨)에만 받고 분류 코드만 남긴다.
        errors_file = tempfile.TemporaryFile() if classify_errors and not merge_stderr else None
        try:
            proc = subprocess.Popen(argv, cwd=REPO, stdin=subprocess.PIPE if input_text else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT if merge_stderr else (errors_file or subprocess.DEVNULL),
                start_new_session=True)
            if input_text:
                encoded = input_text.encode('utf-8')
                if len(encoded) > 4096:
                    raise ValueError('QUERY_TOO_LARGE')
                proc.stdin.write(encoded)
                proc.stdin.close()
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        item['status'] = 'TIMEOUT'
                        break
                    if not selector.select(min(remaining, .2)):
                        continue
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk:
                        selector.unregister(proc.stdout)
                        break
                    item['bytes_read'] += len(chunk)
                    if item['bytes_read'] > max_bytes:
                        item['status'] = 'OUTPUT_LIMIT'
                        break
                    pending += chunk
                    while b'\n' in pending:
                        line, pending = pending.split(b'\n', 1)
                        item['lines_read'] += 1
                        value = line.decode('utf-8', errors='strict')
                        value = transform(value) if transform else value
                        if value is not None:
                            lines.append(value)
                    if len(pending) > 65536:
                        item['status'] = 'LINE_LIMIT'
                        break
            if item['status'] == 'UNAVAILABLE':
                if pending:
                    item['lines_read'] += 1
                    value = pending.decode('utf-8', errors='strict')
                    value = transform(value) if transform else value
                    if value is not None:
                        lines.append(value)
                item['exit_code'] = proc.wait(timeout=max(.01, timeout-(time.monotonic()-started)))
                item['status'] = 'OK' if proc.returncode == 0 else 'COMMAND_FAILED'
        except subprocess.TimeoutExpired:
            item['status'] = 'TIMEOUT'
        except (ValueError, UnicodeError):
            item['status'] = 'INVALID_OUTPUT'
        except OSError:
            item['status'] = 'UNAVAILABLE'
        finally:
            if proc is not None:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                proc.wait()
                for stream in (proc.stdin, proc.stdout):
                    if stream and not stream.closed:
                        stream.close()
            if errors_file is not None:
                try:
                    if item['status'] == 'COMMAND_FAILED':
                        errors_file.seek(0)
                        item['error_codes'] = error_codes(errors_file.read(4096).decode('utf-8', errors='replace'))
                finally:
                    errors_file.close()
            item.update(ended_at=now(), elapsed_ms=round((time.monotonic()-started)*1000, 3))
            self.commands.append(item)
        return '\n'.join(lines) if item['status'] == 'OK' else None


def trace_filter(request_ids, errors):
    def keep(line):
        if 'DG_TRACE_UNAVAILABLE' in line or 'DG_TRACE_WRITE_FAILED' in line:
            errors.add('TRACE_WRITE_FAILED')
        if 'DG_TRACE ' not in line or not any(rid in line for rid in request_ids):
            return None
        value = json.loads(line.split('DG_TRACE ', 1)[1])
        if value.get('requestId') not in request_ids:
            return None
        # 추가 필드가 있어도 본문·IP·인증 정보를 보내지 않는다.
        return 'DG_TRACE ' + json.dumps({k:value.get(k) for k in TRACE_KEYS}, separators=(',', ':'))
    return keep


def lag_line(line):
    parts = line.split()
    if parts[:6] == ['GROUP', 'TOPIC', 'PARTITION', 'CURRENT-OFFSET', 'LOG-END-OFFSET', 'LAG']:
        return ' '.join(parts[:6])
    streams = {('log-group', 'log-topic'), ('ai-service-group', 'ai-request-topic'),
               ('ai-result-group', 'ai-result-topic'), ('waf-detection-group', 'waf-detection-topic')}
    if len(parts) >= 6 and tuple(parts[:2]) in streams and all(re.fullmatch(r'[0-9]+|-', s) for s in parts[2:6]):
        return ' '.join(parts[:6])
    return None


def discover(runner):
    template = '{"id":{{json .ID}},"service":{{json (.Label "com.docker.compose.service")}}}'
    text = runner.run('containers_discover', ['sudo', '-n', 'docker', 'ps', '--no-trunc',
        '--filter', 'label=com.docker.compose.project='+PROJECT, '--format', template])
    ids = {}
    if text is not None:
        for line in text.splitlines():
            row = json.loads(line)
            service, cid = row.get('service'), row.get('id')
            if service in SERVICES and isinstance(cid, str) and re.fullmatch(r'[a-f0-9]{64}', cid):
                if service in ids:
                    raise ValueError('DUPLICATE_SERVICE')
                ids[service] = cid
    return ids


def resources(runner, ids):
    if not ids:
        return None
    template = '{"service":{{json (index .Config.Labels "com.docker.compose.service")}},"image_id":{{json .Image}},"state":{{json .State.Status}},"health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}},"restart_count":{{.RestartCount}},"started_at":{{json .State.StartedAt}}}'
    state = runner.run('containers_state', ['sudo', '-n', 'docker', 'inspect', '--format', template, *ids.values()])
    stats = runner.run('docker_stats', ['sudo', '-n', 'docker', 'stats', '--no-stream', '--format', 'json', *ids.values()])
    if state is None or stats is None:
        return None
    states = [json.loads(line) for line in state.splitlines() if line.strip()]
    by_id = {cid:service for service,cid in ids.items()}
    samples = []
    for line in stats.splitlines():
        row = json.loads(line)
        service = next((s for cid,s in by_id.items() if cid.startswith(row.get('ID', '?'))), None)
        if service is None:
            raise ValueError('UNKNOWN_STATS_CONTAINER')
        samples.append(dict(Name=service, **{k:row.get(k) for k in ('CPUPerc', 'MemPerc', 'MemUsage')}))
    return dict(at=now(), containers=samples, states=states)


def collect(config, runner=None):
    runner = runner or Runner()
    result = dict(schema=SCHEMA, mode=config['mode'], run_id=config['run_id'], started_at=now(),
                  load_generated=False, lag_text=None, database_text=None, trace_text=None,
                  resources=None, commands=runner.commands)
    errors = set()
    ids = discover(runner)
    result['missing_services'] = sorted(SERVICES-set(ids))
    if config['mode'] == 'check':
        head = runner.run('app_sha', ['git', 'rev-parse', 'HEAD'])
        result['app_sha'] = head.strip() if head is not None else None
    if config['mode'] in ('pipeline', 'check'):
        kafka, db, backend = (ids.get(key) for key in ('kafka', 'db', 'backend'))
        if kafka and config.get('include_lag', True):
            result['lag_text'] = runner.run('kafka_lag', ['sudo', '-n', 'docker', 'exec', kafka,
                'kafka-consumer-groups', '--bootstrap-server', 'kafka:29092', '--all-groups', '--describe'],
                timeout=20, transform=lag_line)
        if db:
            def db_line(line):
                value = json.loads(line)
                return json.dumps({k:value.get(k) for k in DB_KEYS}, separators=(',', ':'))
            mysql_argv = ['sudo', '-n', 'docker', 'exec', '-i', db,
                'sh', '-c', 'test -n "$MYSQL_USER" && MYSQL_PWD="$MYSQL_PASSWORD" exec mysql '
                '-u "$MYSQL_USER" -D security_db --connect-timeout=3 --default-character-set=utf8mb4 '
                '--batch --raw --skip-column-names']
            result['database_text'] = runner.run('database', mysql_argv, input_text=config['database_sql'],
                transform=db_line, classify_errors=True)
            if config['mode'] == 'check':
                # 회차 시작 전 최대 로그 id(기본 키 조회). 이후 수집은 이 id보다 큰 행만 읽는다.
                result['log_id_floor'] = runner.run('log_id_floor', mysql_argv,
                    input_text='SET SESSION MAX_EXECUTION_TIME=3000;\nSELECT COALESCE(MAX(id),0) FROM network_logs;\n',
                    transform=lambda line: line if re.fullmatch(r'\d{1,19}', line) else None, classify_errors=True)
        request_ids = set(config['request_ids'])
        if result['database_text'] is not None:
            request_ids.update(json.loads(line)['requestId'] for line in result['database_text'].splitlines())
        if backend:
            flags = runner.run('trace_enabled', ['sudo', '-n', 'docker', 'exec', backend, 'printenv', 'PIPELINE_TRACE_ENABLED'])
            result['trace_enabled'] = flags.strip().lower() == 'true' if flags is not None else None
            result['trace_text'] = runner.run('pipeline_traces', ['sudo', '-n', 'docker', 'logs', '--since',
                config['since'], '--tail', '20000', backend], timeout=12,
                transform=trace_filter(request_ids, errors), max_bytes=16*1024*1024, merge_stderr=True)
            if runner.commands[-1].get('lines_read', 0) >= 20000:
                errors.add('TRACE_TAIL_LIMIT')
    if config['mode'] in ('resources', 'check'):
        result['resources'] = resources(runner, ids)
    result.update(errors=sorted(errors), ended_at=now())
    return result


def main(config):
    if os.name != 'posix' or not (Path(REPO)/'compose.aws.yaml').is_file():
        raise SystemExit(2)
    try:
        result = collect(config)
    except Exception:
        # 예외 메시지에 DB 값·접속 정보가 들어갈 수 있어 고정 코드만 반환한다.
        result = dict(schema=SCHEMA, fatal='REMOTE_COLLECTION_FAILED', load_generated=False)
    print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))
