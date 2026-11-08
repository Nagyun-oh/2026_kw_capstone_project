"""EC2 SSH 수집 어댑터. 앱 요청·부하·상태 변경 없이 기존 파서를 재사용한다."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import subprocess
import time

from e2e_core import database_sql, epoch, parse_database, parse_traces, REQUEST_ID
from metrics import parse_lag
from pipeline import lag_complete, partition_keys

HERE = Path(__file__).resolve().parent
SCHEMA = 'dualguard-ec2-collection-v1'
MODES = {'pipeline', 'resources', 'check'}


def now():
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SSHSettings:
    host: str = field(repr=False)
    identity_file: Path = field(repr=False)
    host_key_alias: str | None = field(default=None, repr=False)

    def __post_init__(self):
        # 키·서버 주소는 명령 실행에만 쓰고 수집 결과·오류·repr에 기록하지 않는다.
        for value in (self.host, self.host_key_alias):
            if value is not None and (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', value)):
                raise ValueError('SSH 호스트 또는 호스트 키 별칭 형식을 확인하세요.')
        object.__setattr__(self, 'identity_file', Path(self.identity_file))

    def argv(self):
        options = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UpdateHostKeys=no', '-o', 'IdentitiesOnly=yes', '-o', 'PasswordAuthentication=no',
            '-o', 'ConnectTimeout=5', '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=2', '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no']
        if self.host_key_alias:
            options.extend(['-o', 'HostKeyAlias='+self.host_key_alias])
        return options + ['-i', str(self.identity_file), 'ubuntu@'+self.host, 'python3 -']


def worker_request(run_id, since, request_ids=(), mode='check', include_lag=True):
    if (not isinstance(run_id, str) or not re.fullmatch(r'[A-Za-z0-9_+.-]{1,160}', run_id)
            or run_id in ('.', '..') or mode not in MODES):
        raise ValueError('수집 실험 ID·모드 형식을 확인하세요.')
    # lag 조회(kafka-consumer-groups CLI)는 JVM을 새로 띄워 측정 대상 CPU를 쓴다.
    # 부하 중 pipeline 수집에서만 생략할 수 있고, check 수집은 항상 lag를 포함한다.
    if type(include_lag) is not bool or (not include_lag and mode != 'pipeline'):
        raise ValueError('lag 생략은 pipeline 수집에서만 허용됩니다.')
    if (not isinstance(since, str) or len(since) > 40 or epoch(since) is None
            or not re.fullmatch(r'[0-9T:.+Z-]+', since)):
        raise ValueError('로그 시작 시각은 오프셋이 있는 ISO 형식이어야 합니다.')
    if isinstance(request_ids, (str, bytes)):
        raise ValueError('요청 ID 목록 형식을 확인하세요.')
    ids = list(request_ids)
    if len(ids) > 2000 or any(not isinstance(rid, str) or not REQUEST_ID.fullmatch(rid) for rid in ids):
        raise ValueError('요청 ID는 최대 2000개의 WAF 생성 32자리 ID여야 합니다.')
    return dict(mode=mode, run_id=run_id, since=since, request_ids=sorted(set(ids)), include_lag=include_lag,
                database_sql='SET SESSION MAX_EXECUTION_TIME=3000;\n'+database_sql(run_id))


def worker_script(config):
    return (HERE/'ec2_collection_worker.py').read_text(encoding='utf-8') + '\nmain(' + repr(config) + ')\n'


def parse_resources(value):
    if not isinstance(value, dict) or not isinstance(value.get('containers'), list) or not value['containers']:
        raise ValueError('컨테이너 자원 표본이 없습니다.')
    rows, names = [], set()
    allowed = {'backend', 'frontend', 'ai', 'db', 'kafka', 'zookeeper', 'waf', 'fluent-bit', 'juiceshop'}
    for row in value['containers']:
        if row.get('Name') not in allowed or row['Name'] in names:
            raise ValueError('컨테이너 식별값 오류')
        names.add(row['Name'])
        for key in ('CPUPerc', 'MemPerc'):
            number = float(str(row.get(key, '')).removesuffix('%'))
            if not math.isfinite(number) or number < 0:
                raise ValueError('컨테이너 자원 값 오류')
        rows.append({k:row.get(k) for k in ('Name', 'CPUPerc', 'MemPerc', 'MemUsage')})
    states = value.get('states')
    if (not isinstance(states, list) or {r.get('service') for r in states} != names
            or len(states) != len(names)):
        raise ValueError('컨테이너 상태 표본 누락')
    return dict(at=value.get('at'), containers=rows,
                states=[{k:r.get(k) for k in ('service', 'image_id', 'state', 'health', 'restart_count', 'started_at')}
                        for r in states])


def parse_collection(value, config, expected_keys=()):
    if (not isinstance(value, dict) or value.get('schema') != SCHEMA
            or value.get('run_id') != config['run_id'] or value.get('mode') != config['mode']
            or value.get('load_generated') is not False):
        raise ValueError('원격 수집 응답 형식이 다릅니다.')
    errors = list(value.get('errors', []))
    commands = value.get('commands')
    if not isinstance(commands, list) or not commands:
        raise ValueError('원격 명령 실행 근거가 없습니다.')
    safe_commands=[]
    for item in commands:
        safe_commands.append({k:item.get(k) for k in ('check', 'started_at', 'ended_at', 'timeout_seconds',
            'status', 'exit_code', 'bytes_read', 'lines_read', 'elapsed_ms')})
        if item.get('status') != 'OK':
            errors.append('COMMAND_'+str(item.get('check'))+'_'+str(item.get('status')))
    result = dict(schema=SCHEMA, mode=config['mode'], run_id=config['run_id'],
        started_at=value.get('started_at'), ended_at=value.get('ended_at'),
        lag=None, database=None, traces=None, resources=None, commands=safe_commands)
    if config['mode'] == 'check':
        head=value.get('app_sha')
        if not isinstance(head,str) or not re.fullmatch(r'[a-f0-9]{40}',head):
            errors.append('APP_SHA_UNAVAILABLE')
        else:
            result['app_sha']=head
    if value.get('missing_services'):
        errors.append('MISSING_SERVICES')
    if config['mode'] in ('pipeline', 'check'):
        text=value.get('lag_text')
        if not config.get('include_lag', True):
            # 요청하지 않은 lag는 수집 실패가 아니다. 결과의 lag는 None으로 둔다.
            if text is not None:
                errors.append('LAG_NOT_REQUESTED')
        elif not isinstance(text,str):
            errors.append('LAG_UNAVAILABLE')
        else:
            snap=dict(at=value.get('ended_at'), started_at=value.get('started_at'), code=0, rows=parse_lag(text))
            if not lag_complete(snap,set(expected_keys)):
                errors.append('LAG_INCOMPLETE')
            result['lag']=snap
        text=value.get('database_text')
        if not isinstance(text,str):
            errors.append('DATABASE_UNAVAILABLE')
        else:
            result['database']=parse_database(text)
        text=value.get('trace_text')
        if not isinstance(text,str):
            errors.append('TRACE_UNAVAILABLE')
        else:
            allowed=set(config['request_ids']) | {r['requestId'] for r in result['database'] or []}
            result['traces']=parse_traces(text)
            if any(t['requestId'] not in allowed for t in result['traces']):
                raise ValueError('수집 범위 밖의 요청 계측이 반환됐습니다.')
        if value.get('trace_enabled') is not True:
            errors.append('TRACE_NOT_ENABLED')
    if config['mode'] in ('resources', 'check'):
        if value.get('resources') is None:
            errors.append('RESOURCES_UNAVAILABLE')
        else:
            result['resources']=parse_resources(value['resources'])
    result.update(errors=sorted(set(errors)), collection_status='INCOMPLETE' if errors else 'COLLECTED')
    return result


class SSHCollection:
    """동기 수집 인터페이스. E2E 제어기는 asyncio.to_thread로 호출한다."""
    def __init__(self, settings, *, run=None):
        self.settings, self.run = settings, run or subprocess.run
        self.last_record = None

    def collect(self, run_id, since, request_ids=(), *, mode='pipeline', expected_keys=(), include_lag=True):
        config=worker_request(run_id,since,request_ids,mode,include_lag)
        started=time.perf_counter()
        record=dict(check='ssh_'+mode, started_at=now(), timeout_seconds=80, status='UNAVAILABLE', exit_code=None)
        result=None
        try:
            response=self.run(self.settings.argv(), input=worker_script(config), text=True,
                encoding='utf-8', errors='strict', capture_output=True, timeout=80, shell=False)
            record['exit_code']=response.returncode
            if response.returncode:
                record['status']='SSH_FAILED'
            elif len(response.stdout.encode('utf-8')) > 8*1024*1024:
                record['status']='OUTPUT_LIMIT'
            else:
                result=parse_collection(json.loads(response.stdout),config,expected_keys)
                record['status']='OK'
        except subprocess.TimeoutExpired:
            record['status']='TIMEOUT'
        except (ValueError, TypeError, KeyError, UnicodeError):
            record['status']='INVALID_OUTPUT'
        except OSError:
            record['status']='UNAVAILABLE'
        record.update(ended_at=now(), elapsed_ms=round((time.perf_counter()-started)*1000,3))
        self.last_record=record
        if result is None:
            result=dict(schema=SCHEMA, mode=mode, run_id=run_id, collection_status='INCOMPLETE',
                errors=[record['status']], lag=None, database=None, traces=None, resources=None, commands=[])
        result['transport']=record
        return result
