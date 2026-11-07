"""P7 소량 연결 검증의 제한·복구·판정. EC2 부하 실행 제한은 해제하지 않는다."""
import ipaddress
import json
import re
import subprocess
import time
import urllib.error

from e2e_core import client_record
from e2e_environment import select_environment
from e2e_remote import HERE
from ec2_watch import epoch_ms
from run_e2e import build_request, request_opener


def with_generator(original, source):
    if not isinstance(original, str) or len(original) > 2048:
        raise ValueError('EXCLUSION_FORMAT')
    address = ipaddress.ip_address(source)
    if not address.is_global or address.version != 4:
        raise ValueError('PUBLIC_IPV4_REQUIRED')
    entries = original.replace(',', ' ').split()
    for item in entries:
        ipaddress.ip_address(item)
    return original if source in entries else (original+',' if original else '')+source


def owned_blacklist(baseline, current, run_id, probe_id):
    """기존 등록과 다른 실험의 등록은 삭제 대상으로 삼지 않는다."""
    old = {row['id'] for row in baseline}
    new = [row for row in current if row['id'] not in old]
    if any(row.get('runId') != run_id or row.get('requestId') != probe_id for row in new):
        raise ValueError('BLACKLIST_OWNERSHIP_UNCERTAIN')
    return [row['id'] for row in new]


def public_state(value):
    private = value.get('private', {})
    source = private.get('source_ipv4')
    return dict(schema=value.get('schema'), at=value.get('at'), status=value.get('status'),
        error_code=value.get('error_code'), commands=value.get('commands'),
        reconfigure_attempted=value.get('reconfigure_attempted', False),
        command_succeeded=value.get('command_succeeded'), app_sha=private.get('app_sha'),
        waf=private.get('waf'), nginx_test_ok=private.get('nginx_test_ok'),
        generator_excluded=source in private.get('exclusions','').replace(',', ' ').split(),
        exclusion_count=len(private.get('exclusions','').replace(',', ' ').split()),
        blacklist=private.get('blacklist'), https_source=private.get('https_source'))


class Control:
    def __init__(self, settings):
        self.settings = settings

    def call(self, action='inspect', **kwargs):
        config = dict(action=action, **kwargs)
        source = (HERE/'ec2_collection_worker.py').read_text(encoding='utf-8')+'\n'
        source += (HERE/'ec2_connection_worker.py').read_text(encoding='utf-8')
        source += '\nconnection_main('+repr(config)+')\n'
        proc = subprocess.run(self.settings.argv(), input=source.encode(), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=115)
        if proc.returncode or len(proc.stdout) > 256*1024:
            raise RuntimeError('SSH_CONTROL_FAILED')
        value = json.loads(proc.stdout)
        if value.get('schema') != 'dualguard-ec2-connection-control-v1':
            raise RuntimeError('CONTROL_SCHEMA_INVALID')
        return value


class RequestBudget:
    """정상 3건·probe 1건·복구 확인 1건으로 고정한 소량 요청기."""
    def __init__(self):
        self.used = 0
        self.probes = 0

    def send(self, run_id, fixture, sequence, clock, *, probe=False, recovery=False):
        if self.used >= 5 or (probe and self.probes) or (recovery and probe):
            raise ValueError('P7_REQUEST_BUDGET_EXCEEDED')
        if not re.fullmatch(r'[A-Za-z0-9+._-]+-ec2-connection-r[0-9]{2}', run_id):
            raise ValueError('RUN_ID_INVALID')
        self.used += 1
        self.probes += int(probe)
        env = select_environment('ec2')
        kind = 'probe' if probe else 'background'
        phase = 'warmup' if recovery else 'measurement'
        req = build_request(phase, sequence, run_id, fixture, kind=kind, environment=env)
        sent, mono = epoch_ms(), time.perf_counter()
        try:
            response = request_opener(env).open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            # 사용자 계정과 무관한 시험 fixture라도 JuiceShop 로그인 토큰은 보존하지 않는다.
            if len(response.read(1048577)) > 1048576:
                raise ValueError('RESPONSE_TOO_LARGE')
            return client_record(phase, kind, sequence, dict(response.headers), response.code,
                (time.perf_counter()-mono)*1000, sent, epoch_ms(), mono, clock=clock)


def connection_checks(clients, database, traces, browser):
    measured = [c for c in clients if c['phase']=='measurement']
    probes = [c for c in measured if c['kind']=='probe']
    checks = dict(request_count=len(measured)==4, http_200=all(c['status']==200 for c in measured),
        unique_request_ids=len({c['requestId'] for c in measured})==4)
    db = {row['requestId']:row for row in database}
    checks['database_once'] = len(database)==len(db)==4 and all(c['requestId'] in db for c in measured)
    checks['log_committed'] = all(any(t['stage']=='LOG_COMMITTED' and t['requestId']==c['requestId'] for t in traces) for c in measured)
    checks['ai_committed'] = all(any(t['stage']=='AI_RESULT_COMMITTED' and t['requestId']==c['requestId'] for t in traces) for c in measured)
    checks.update(probe_two_sources=False, alert_sent=False, browser_received=False, browser_dom=False, single_popup=False)
    if len(probes)==1 and probes[0]['requestId'] in db:
        rid = probes[0]['requestId']
        row = db[rid]
        checks['probe_two_sources'] = row['aiRows']==row['wafRows']==1 and bool(row['alertId'])
        checks['alert_sent'] = any(t['stage']=='ALERT_SEND_RETURNED' and t['requestId']==rid and
            t['alertId']==row['alertId'] and t['revision']>=row['revision'] and set(t['sources'])=={'AI','WAF'} for t in traces)
        events = [e for e in browser if e.get('alertId')==row['alertId']]
        for kind in ('received','dom'):
            sources = {s for e in events if e['kind']==kind for s in e.get('sources',[])}
            checks['browser_'+kind] = sources=={'AI','WAF'}
        checks['single_popup'] = bool(events) and all(e.get('duplicateCount',1)==1 for e in events)
    return checks


async def observe_threat_row(page, threat_id, log_id):
    """블랙리스트에도 같은 로그 버튼이 있으므로 위협 표 안에서만 확인한다."""
    panel = page.locator('section[aria-label="위협 탐지 목록"]')
    field = panel.locator('input[name="threatId"]')
    await field.fill(str(threat_id))
    await field.locator('xpath=ancestor::form').get_by_role('button',name='검색',exact=True).click()
    table = panel.get_by_role('region',name='위협 탐지 데이터 표',exact=True)
    await table.get_by_role('button',name=f'원본 로그 {log_id} 상세 보기',exact=True).wait_for(state='visible',timeout=15000)
