"""확정 EC2 부하 계약·결과 판정·입력 RPS/처리 EPS 구분. 네트워크 호출 없음."""
import hashlib
import json
import math
from pathlib import Path

from e2e_core import epoch,evaluate
from pipeline import distribution

PROFILE=Path(__file__).parent/'profiles/ec2-e2e-v1.json'


def validate_contract(policy):
    if (policy.get('version')!='ec2-e2e-v1' or policy.get('executable') is not True
            or policy.get('execution_profile')!='scripts/testing/run_ec2_e2e.py'):
        raise ValueError('EC2_CONTRACT_NOT_EXECUTABLE')
    w=policy['workload']
    clock=policy.get('clock_policy',{})
    if (clock.get('require_consistent_offset_interval') is not True or clock.get('max_age_seconds')!=300
            or clock.get('cross_domain_latency_subtraction') is not False
            or clock.get('width_role')!='diagnostic_only_independent_server_and_pc_clock_domains'):
        raise ValueError('EC2_CLOCK_DOMAIN_CONTRACT_INVALID')
    if (w['total_rates_per_second']!=[1,3,5] or w['measurement_seconds']!=120 or
            w['warmup_seconds_per_repetition']!=30 or w['repetitions_per_rate']!=3 or
            w['pilot_seconds']!=60 or w['pilot_rate']!=1 or w['probe_interval_seconds']!=10 or
            w['final_observation_seconds']!=60 or w['lag_zero_consecutive_samples']!=2 or
            w['lag_confirmation_interval_seconds']!=10):
        raise ValueError('EC2_WORKLOAD_CONTRACT_CHANGED')
    for key in ('ai_server_e2e_p95_ms','waf_server_e2e_p95_ms'):
        if policy['initial_targets'].get(key)!=3000: raise ValueError('EC2_SLO_CONTRACT_CHANGED')
    for v in policy['stop'].values():
        if type(v) not in (int,float) or not math.isfinite(v) or v<=0:
            raise ValueError('EC2_STOP_VALUE_INVALID')
    return policy


def load_contract():
    raw=PROFILE.read_bytes()
    return validate_contract(json.loads(raw)),hashlib.sha256(raw).hexdigest()


def selected_contract(policy,mode,rate):
    validate_contract(policy)
    if mode not in ('pilot','formal') or rate not in (1,3,5) or (mode=='pilot' and rate!=1):
        raise ValueError('EC2_MODE_RATE_INVALID')
    return {**policy,'workload':{**policy['workload'],
        'measurement_seconds':60 if mode=='pilot' else 120}}


def assess(clients,traces,database,browser,spec,*,rate,elapsed,final_lag,errors=(),abort=None,complete=False):
    result=evaluate(clients,traces,database,browser,spec,errors=errors,abort=abort,elapsed=elapsed,
        final_lag=final_lag,observation_complete=complete)
    rows=[c for c in clients if c['phase']=='measurement']
    seconds=spec['workload']['measurement_seconds']
    expected=rate*seconds
    reasons=result['reasons'] if result['verdict']!='PASS' else []
    if len(rows)!=expected:
        if result['verdict']!='FAIL': result['verdict']='INCONCLUSIVE'
        reasons.append('입력 요청 수·확정 부하 조건 불일치')
    probe_count=sum(c['kind']=='probe' for c in rows)
    if probe_count!=seconds//10:
        if result['verdict']!='FAIL': result['verdict']='INCONCLUSIVE'
        reasons.append('확정 probe 송신 수 불일치')
    if complete and not final_lag:
        result['verdict']='FAIL'
        reasons.append('60초 내 업무 완료·연속 lag 0 확인 실패')
    for stage in ('LOG_COMMITTED','AI_RESULT_COMMITTED','WAF_COMMITTED'):
        ids={c['requestId'] for c in rows}
        values=[t['requestId'] for t in traces if t['stage']==stage and t['requestId'] in ids]
        if len(values)!=len(set(values)):
            result['verdict']='FAIL'
            reasons.append(stage+' 중복 커밋 계측')
    completed={t['requestId'] for t in traces if t['stage']=='AI_RESULT_COMMITTED'}
    recorded={r['requestId'] for r in database}
    ids={c['requestId'] for c in rows}
    result['rates']=dict(target_input_rps=rate,expected_requests=expected,
        http_requests=len(rows),http_rps_during_observed_send_window=len(rows)/elapsed if elapsed else None,
        server_ingress_eps_per_planned_seconds=len(ids)/seconds,
        committed_logs=len(recorded & ids),ai_completed_requests=len(completed & ids),
        note='유입 EPS는 계획 구간당 고유 요청 수. 부하 중 처리 완료 EPS는 progress.jsonl의 관측 구간별 차이로 판단한다. 최종 drain 건수를 부하 중 처리량으로 사용하지 않는다.')
    result['reasons']=sorted(set(reasons)) or ['확정 EC2 서버 지연·정합성·알림·적체 해소 기준 충족']
    return result


def summarize_stage(runs):
    if len(runs)!=3 or len({m['id'] for m,_ in runs})!=3:
        raise ValueError('THREE_DISTINCT_FORMAL_RUNS_REQUIRED')
    def conditions(m):
        return {k:m.get(k) for k in ('rate','seconds','warmup_seconds','fixture_sha256','contract_sha256',
            'runner_files_sha256','app_sha','images','target_url','dashboard_url','versions')}
    first=conditions(runs[0][0])
    if any(m.get('mode')!='formal' or m.get('schema')!='ec2-e2e-v1' or m.get('seconds')!=120
            or m.get('warmup_seconds')!=30 or m.get('rate') not in (1,3,5) or conditions(m)!=first for m,_ in runs):
        raise ValueError('FORMAL_RUN_CONDITIONS_DIFFER')
    if any(v is None for v in first.values()): raise ValueError('COMPARISON_CONDITIONS_MISSING')
    verdicts={r['verdict'] for _,r in runs}
    pooled={}
    for m,r in runs:
        if r.get('verdict') not in ('PASS','FAIL','INCONCLUSIVE'): raise ValueError('VERDICT_INVALID')
        if r['verdict']=='PASS' and (m.get('state')!='COMPLETED' or not r.get('latency_samples_ms')):
            raise ValueError('PASS_EVIDENCE_MISSING')
        for key,values in r.get('latency_samples_ms',{}).items():
            if not isinstance(values,list) or any(type(v) not in (int,float) or not math.isfinite(v) or v<0 for v in values):
                raise ValueError('LATENCY_SAMPLES_INVALID')
            pooled.setdefault(key,[]).extend(values)
    return dict(verdict='FAIL' if 'FAIL' in verdicts else 'PASS' if verdicts=={'PASS'} else 'INCONCLUSIVE',
        ids=[m['id'] for m,_ in runs],conditions=first,pooled_stats_ms={k:distribution(v) for k,v in pooled.items()},
        note='3회 모두 PASS여야 단계 PASS. p99를 평균하지 않고 원본 표본에서 다시 계산한다.')
