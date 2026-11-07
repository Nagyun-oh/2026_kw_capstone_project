"""v2의 순수 파싱·요청 연결·판정. 서비스·브라우저는 호출하지 않는다."""
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
from pipeline import distribution

HERE = Path(__file__).parent
SPEC = HERE.parents[1] / 'docs/testing/local/e2e-plan-v2.json'
FIXTURE = HERE / 'fixtures/juiceshop-login.json'
REQUEST_ID = re.compile(r'^[0-9a-fA-F]{32}$')
ALERT_ID = re.compile(r'^[0-9a-fA-F-]{36}$')
STAGES = {'LOG_COMMITTED', 'AI_RESULT_COMMITTED', 'AI_RESULT_DUPLICATE',
          'WAF_COMMITTED', 'ALERT_SEND_BEGIN', 'ALERT_SEND_RETURNED'}


class ClockObservationError(ValueError):
    """응답 식별값은 있지만 현재 보정 구간으로 시각을 확인하지 못했다."""


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def epoch(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.timestamp() if parsed.tzinfo else None
    except (ValueError, AttributeError, OverflowError):
        return None


def fixture(path=FIXTURE):
    raw = Path(path).read_bytes()
    value = json.loads(raw)
    if (value.get('method') != 'POST' or value.get('path') != '/rest/user/login'
            or value.get('expectedStatus') != 200
            or set(value.get('expectedSources', [])) != {'AI', 'WAF'}
            or not isinstance(value.get('body'), dict)):
        raise ValueError('검증된 로컬 JuiceShop fixture 형식이 필요합니다.')
    if set(value.get('headers', {})) - {'Content-Type', 'Accept', 'User-Agent'}:
        raise ValueError('fixture에 쿠키·인증·전달 헤더를 넣을 수 없습니다.')
    return value, hashlib.sha256(raw).hexdigest()


def client_record(phase, kind, sequence, headers, status, duration_ms, sent_ms, ended_ms, c0=None, *, clock=None,
                  client_clock_resolution_ms=0):
    headers = {k.lower(): str(v) for k, v in headers.items()}
    request_id = headers.get('x-request-id', '')
    try:
        start = float(headers.get('x-dualguard-request-start', ''))
    except ValueError:
        start = None
    if not REQUEST_ID.fullmatch(request_id) or not finite(start) or start <= 0:
        raise ValueError('WAF의 requestId·정밀 시각 응답 헤더가 없습니다.')
    if phase not in {'warmup', 'measurement'} or kind not in {'probe', 'background'}:
        raise ValueError('실험 phase·kind 오류')
    if not all(finite(v) for v in (duration_ms, sent_ms, ended_ms)) or duration_ms < 0 or ended_ms < sent_ms:
        raise ValueError('클라이언트 시각 오류')
    if client_clock_resolution_ms not in (0,1):
        raise ValueError('지원하지 않는 클라이언트 시각 해상도')
    # HTTP 송신~응답 사이여야 같은 머신/VM의 UTC 시계가 모순되지 않는다.
    if clock is None:
        if not sent_ms - 100 <= start * 1000 <= ended_ms + 100:
            raise ValueError('WAF·발생기 시계 차이가 허용 관측 오차 100ms를 넘었습니다.')
    else:
        from ec2_watch import ingress_in_clock_interval
        calibrations = [clock, *clock.get('previous_calibrations', [])]
        if not any(ingress_in_clock_interval(start*1000,sent_ms,ended_ms,item,
                       ingress_resolution_ms=1,client_resolution_ms=client_clock_resolution_ms)
                   for item in calibrations):
            raise ClockObservationError('WAF 시각이 EC2 보정 구간 밖이거나 보정이 오래됐습니다.')
    return dict(phase=phase, kind=kind, sequence=int(sequence), requestId=request_id,
                ingress=start, status=int(status), duration_ms=duration_ms,
                sent_ms=sent_ms, ended_ms=ended_ms, c0=c0,
                clock_resolution_ms=dict(ingress=1,client=client_clock_resolution_ms))


def parse_points(path, *, partial=False, clock=None):
    rows = []
    text = Path(path).read_text(encoding='utf-8')
    lines = text.splitlines()
    if partial and text and not text.endswith('\n'):
        lines = lines[:-1]
    for line in lines:
        point = json.loads(line)
        if point.get('type') != 'Point' or point.get('metric') != 'dg_client_request':
            continue
        tags = point['data']['tags']
        rows.append(client_record(tags['phase'], tags['kind'], tags['sequence'],
                    {'x-request-id': tags['request_id'], 'x-dualguard-request-start': tags['ingress']},
                    tags['status'], point['data']['value'], float(tags['sent_at_ms']), float(tags['ended_at_ms']),
                    clock=clock,client_clock_resolution_ms=1))
    return rows


def parse_traces(text):
    rows = []
    for line in text.splitlines():
        if 'DG_TRACE ' not in line:
            continue
        value = json.loads(line.split('DG_TRACE ', 1)[1])
        if value.get('schema') != 'dualguard-trace-v1' or value.get('stage') not in STAGES or epoch(value.get('at')) is None:
            raise ValueError('계측 이벤트 형식 오류')
        if value.get('requestId') is not None and not REQUEST_ID.fullmatch(value['requestId']):
            raise ValueError('계측 요청 ID 오류')
        # 원문 로그·IP·본문·토큰은 보존하지 않는다.
        rows.append({k: value.get(k) for k in ('stage', 'outcome', 'requestId', 'logId',
                      'threatId', 'alertId', 'revision', 'sources', 'at')})
    return rows


def browser_record(value, at):
    kind = value.get('kind')
    if kind in {'ready', 'disconnected', 'heartbeat'}:
        return dict(kind=kind, observed=at)
    if kind not in {'received', 'dom'} or not ALERT_ID.fullmatch(value.get('alertId', '')):
        raise ValueError('브라우저 계측 형식 오류')
    if type(value.get('revision')) is not int or value['revision'] < 1:
        raise ValueError('브라우저 revision 오류')
    sources = value.get('sources')
    if not isinstance(sources, list) or not sources or set(sources) - {'AI', 'WAF'}:
        raise ValueError('브라우저 탐지 출처 오류')
    if type(value.get('duplicateCount', 1)) is not int or value.get('duplicateCount', 1) < 1:
        raise ValueError('브라우저 DOM 중복 수 오류')
    return dict(kind=kind, alertId=value['alertId'], revision=value['revision'],
                sources=sorted(set(sources)), observed=at, browserAt=value.get('browserAt'),
                duplicateCount=value.get('duplicateCount', 1))


def parse_database(text):
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    for row in rows:
        if (not isinstance(row, dict) or not REQUEST_ID.fullmatch(row.get('requestId', ''))
                or type(row.get('logId')) is not int or row['logId'] < 1
                or row.get('phase') not in {'warmup', 'measurement'}
                or row.get('kind') not in {'background', 'probe'}
                or any(type(row.get(k)) is not int or row[k] < 0 for k in ('aiRows', 'wafRows'))):
            raise ValueError('실험 DB 결과 형식 오류')
    return rows


def database_sql(run_id):
    run_hex = run_id.encode('utf-8').hex()
    return f"""START TRANSACTION READ ONLY;
SELECT JSON_OBJECT(
 'requestId',n.request_id,'logId',n.id,
 'phase',JSON_UNQUOTE(JSON_EXTRACT(n.raw_log,'$.test_phase')),
 'kind',JSON_UNQUOTE(JSON_EXTRACT(n.raw_log,'$.test_kind')),
 'sequence',JSON_UNQUOTE(JSON_EXTRACT(n.raw_log,'$.test_seq')),
 'ingress',JSON_UNQUOTE(JSON_EXTRACT(n.raw_log,'$.request_start_epoch_s')),
 'alertId',a.alert_id,'revision',a.revision,
 'aiDetected',a.ai_detected,'wafDetected',a.waf_detected,
 'aiRows',(SELECT COUNT(*) FROM detected_threats t WHERE t.log_id=n.id AND t.threat_type='AI Detection'),
 'wafRows',(SELECT COUNT(*) FROM waf_detections w WHERE BINARY w.request_id=BINARY n.request_id)
)
FROM network_logs n LEFT JOIN request_alerts a
 ON BINARY a.alert_key=BINARY CONCAT('request:',n.request_id)
WHERE BINARY JSON_UNQUOTE(JSON_EXTRACT(IF(JSON_VALID(n.raw_log),n.raw_log,'{{}}'),'$.test_run'))
 = BINARY CONVERT(0x{run_hex} USING utf8mb4)
ORDER BY n.id;
ROLLBACK;
"""


def evaluate(clients, traces, database, browser, spec, *, errors=(), abort=None, elapsed=None,
             final_lag=False, observation_complete=False):
    failures, unknowns = [], list(errors)
    rows = [c for c in clients if c['phase'] == 'measurement']
    ids = [c['requestId'] for c in rows]
    if not rows:
        unknowns.append('측정 phase 요청 없음')
    if len(ids) != len(set(ids)):
        failures.append('서버 requestId 중복')
    if any(c['status'] != 200 for c in rows):
        failures.append('예상 밖 HTTP 상태')
    if not finite(elapsed) or elapsed < spec['workload']['measurement_seconds']:
        unknowns.append('측정 기간 미충족')
    db = {r['requestId']: r for r in database if r['phase'] == 'measurement'}
    if len(db) != len([r for r in database if r['phase'] == 'measurement']):
        failures.append('DB requestId 중복')
    if set(db) != set(ids):
        (failures if observation_complete else unknowns).append('송신·DB 요청 집합 불일치')
    if not final_lag:
        unknowns.append('종료 후 필수 Kafka lag 0 두 번 확인 부족')
    if any(b.get('duplicateCount', 1) > 1 for b in browser if b['kind'] == 'dom'):
        failures.append('동일 알림의 중복 팝업')
    by_request = {}
    for t in traces:
        if t['requestId'] in set(ids):
            by_request.setdefault(t['requestId'], []).append(t)
    values = {k: [] for k in ('http', 'log_ingest', 'ai_segment', 'ai_server', 'waf_server',
              'AI_receive', 'WAF_receive', 'AI_dom', 'WAF_dom')}
    targets = spec['initial_targets']
    missing = {k: 0 for k in values}
    links = []
    for c in rows:
        rid, start = c['requestId'], c['ingress']
        values['http'].append(c['duration_ms']) if c['kind'] == 'background' else None
        events = by_request.get(rid, [])
        def first(stage):
            return min((epoch(t['at']) for t in events if t['stage'] == stage), default=None)
        def delay(key, end, begin):
            if end is None or begin is None or end < begin:
                missing[key] += 1
                unknowns.append(key + ' 시각·표본 미확인')
                return None
            ms = (end - begin) * 1000
            values[key].append(ms)
            return ms
        log_at, ai_at, waf_at = first('LOG_COMMITTED'), first('AI_RESULT_COMMITTED'), first('WAF_COMMITTED')
        delay('log_ingest', log_at, start)
        delay('ai_segment', ai_at, log_at)
        delay('ai_server', ai_at, start)
        row = db.get(rid, {})
        if row:
            if (row.get('phase') != c['phase'] or row.get('kind') != c['kind']
                    or str(row.get('sequence')) != str(c['sequence'])):
                failures.append('응답 ID와 DB 실험 표식의 연결 불일치')
            try:
                same_ingress = abs(float(row['ingress']) - start) <= .002
            except (KeyError, ValueError, TypeError):
                same_ingress = False
            if not same_ingress:
                unknowns.append('WAF 응답·로그 시작 시각 대조 미확인')
        if any((row.get(k) or 0) > 1 for k in ('aiRows', 'wafRows')):
            failures.append('중복 탐지 저장')
        alert_ids = {t['alertId'] for t in events if t.get('alertId')}
        if row.get('alertId'):
            alert_ids.add(row['alertId'])
        if len(alert_ids) > 1:
            failures.append('같은 요청의 알림 ID가 다름')
        alert_id = next(iter(alert_ids), None)
        links.append(dict(requestId=rid, logId=row.get('logId'), alertId=alert_id,
                          kind=c['kind'], sequence=c['sequence']))
        expected_sources = {s for s, key in [('AI', 'aiDetected'), ('WAF', 'wafDetected')] if row.get(key)}
        received_sources = {s for b in browser if b['kind'] == 'received' and b.get('alertId') == alert_id
                            for s in b.get('sources', [])}
        if expected_sources - received_sources:
            (failures if observation_complete else unknowns).append('저장된 탐지의 알림 출처 수신 미확인')
        if expected_sources and not any(b['kind'] == 'received' and b.get('alertId') == alert_id
                and b.get('revision', 0) >= (row.get('revision') or 1) for b in browser):
            (failures if observation_complete else unknowns).append('알림 최신 revision 수신 미확인')
        if waf_at is not None or c['kind'] == 'probe':
            waf_ms = delay('waf_server', waf_at, start)
            if (c['kind'] == 'probe' and waf_ms is not None and targets['waf_server_probe_deadline_ms'] is not None
                    and waf_ms > targets['waf_server_probe_deadline_ms']):
                failures.append('WAF probe 저장 기한 초과')
        if c['kind'] != 'probe':
            continue
        for source in ('AI', 'WAF'):
            produced = any(t['stage'] == 'AI_RESULT_COMMITTED' and t['outcome'] == 'DETECTED'
                           for t in events) if source == 'AI' else waf_at is not None
            sends = [t for t in events if t['stage'] == 'ALERT_SEND_RETURNED'
                     and t.get('alertId') == alert_id and source in (t.get('sources') or [])]
            if produced and not sends:
                (failures if observation_complete else unknowns).append(source + ' 알림 전송 반환 기록 없음')
            for kind, metric, limit in [('received', 'receive', 'browser_source_probe_deadline_ms'),
                                         ('dom', 'dom', 'dom_source_probe_deadline_ms')]:
                observed = min((b['observed'] for b in browser if b.get('kind') == kind
                    and b.get('alertId') == alert_id and source in b.get('sources', [])), default=None)
                ms = delay(source + '_' + metric, observed, c.get('c0'))
                if ms is not None and targets[limit] is not None and ms > targets[limit]:
                    failures.append(source + ' ' + metric + ' 기한 초과')
                elif observed is None and produced and sends and observation_complete:
                    failures.append(source + ' ' + metric + ' 최종 관측 기한까지 미도착')
            if not row.get('aiDetected' if source == 'AI' else 'wafDetected'):
                unknowns.append(source + ' probe 기대 탐지 미확인')
    stats = {k: distribution(v) for k, v in values.items()}
    checks=[('http',targets['http_request_path_p95_ms']),('ai_server',targets['ai_server_e2e_p95_ms'])]
    if 'waf_server_e2e_p95_ms' in targets: checks.append(('waf_server',targets['waf_server_e2e_p95_ms']))
    for key,limit in checks:
        if limit is None: continue
        p95 = stats[key]['p95_ms']
        if p95 is None:
            unknowns.append(key + ' p95 미측정')
        elif p95 > limit:
            failures.append(key + ' p95 기준 초과')
    if not any(c['kind'] == 'probe' for c in rows):
        unknowns.append('측정 probe 없음')
    if abort:
        (failures if abort['verdict'] == 'FAIL' else unknowns).append('자동 중단: ' + abort['code'])
    return dict(version=spec.get('version','local-e2e-v2'), verdict='FAIL' if failures else 'INCONCLUSIVE' if unknowns else 'PASS',
                reasons=sorted(set(failures + unknowns)) or ['출처별 서버·브라우저·DOM 및 정합성 기준 충족'],
                stats_ms=stats, missing=missing, links=links,
                latency_samples_ms=values,
                counts=dict(http=len(rows), db=len(db), probes=sum(c['kind'] == 'probe' for c in rows)))
