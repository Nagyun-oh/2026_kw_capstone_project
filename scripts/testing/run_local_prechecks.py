"""기존 E2E 판정으로 3·5RPS를 각 1회 실행한다. 계정은 숨김 표준 입력으로만 받는다."""
import argparse
from datetime import datetime
import getpass
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from local_browser_login import login_local
import run_e2e
from run_experiment import ROOT, HERE, KST, now, reserve, save, format_record_time


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--start-round', type=int, default=19)
    parser.add_argument('--confirm-ip-policy', action='store_true', required=True)
    args = parser.parse_args(argv)
    if args.start_round < 1:
        parser.error('시작 회차는 양수여야 합니다.')
    group_id = datetime.now(KST).strftime('%Y%m%dT%H%M%S%z') + f'-local-e2e-prechecks-r{args.start_round:02d}'
    output, report = reserve(ROOT, group_id)
    manifest = dict(id=group_id, planned_at=now(), state='PLANNED', purpose='local_precheck_single_run_each',
        rates=[3, 5], repetitions_per_rate=1, measurement_seconds=120, warmup_seconds=30,
        auth_mode='local_browser_form_memory_only', contract_sha256=hashlib.sha256(run_e2e.SPEC.read_bytes()).hexdigest(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        login_helper_sha256=hashlib.sha256((HERE/'local_browser_login.py').read_bytes()).hexdigest())
    plan = f"""# 실험 기록: {datetime.now(KST):%Y/%m/%d} — 로컬 3·5RPS 예비 확인

## 실행 정보

- ID: `{group_id}`
- 계획 시각: {format_record_time(manifest['planned_at'])}
- 상태: PLANNED / 판정: NOT_EVALUATED
- 원본: `{output.as_posix()}`

## S — Situation / T — Task

outbox·Consumer 보완 후 1RPS 3회는 PASS했다. EC2 측정 준비 전 로컬의 3·5RPS 처리·관측 연결을 각각 한 번 확인한다.

## T — Target

- 3RPS·5RPS 각각 워밍업 30초 제외·측정 120초·1회. 기존 v2 회차별 정합성·지연·중단 기준 유지.
- 3RPS PASS일 때만 5RPS 실행. 실패·미확인이면 상승 중단하고 원본 보존.
- 부하별 3회 반복 단계 통과·최대 성능·EC2 성능으로 표현하지 않는다.
- 사용자 제공 계정은 표준 입력으로 받아 localhost:3000 실제 로그인 폼에만 사용한다. 저장·출력·세션 파일 보존 없음.
- 앱·DB·토픽·offset·차단 정책 자동 변경 없음. 기존 자동 중단 감시는 소유한 발생기·브라우저에만 적용.

## A — Action

실행 예정. 각 회차의 원본·STAR-T 보고서를 연결한다.

## R — Result / T — Trouble

아직 미실행. 테스트 완료 후 실제 관측과 한계를 기록한다.
"""
    report.write_text(plan, encoding='utf-8')
    save(output/'manifest.json', manifest)
    results, current, username, password = [], {}, None, None
    original_reserve, original_report = run_e2e.reserve, run_e2e.report
    def remember(root, run_id):
        paths = original_reserve(root, run_id)
        current.update(id=run_id, output=paths[0], report=paths[1])
        return paths
    def precheck_report(man, metrics, out):
        return original_report(man, metrics, out).replace(
            '구분: 기준 측정 한 회차', '구분: 로컬 예비 확인 1회(부하별 3회 단계 판정 아님)')
    try:
        username = getpass.getpass('Local username (hidden, not saved): ')
        password = getpass.getpass('Local password (hidden, not saved): ')
        if not username or not password:
            raise RuntimeError('로컬 로그인 입력 누락')
        from playwright.async_api import Page
        original_wait = Page.wait_for_function
        async def login_then_wait(page, expression, *pos, **kw):
            if expression == 'window.__dgReady === true':
                await login_local(page, username, password, original_wait)
                with (output/'events.jsonl').open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(dict(at=now(), event='authenticated_browser_ready', run_id=current.get('id'))) + '\n')
            return await original_wait(page, expression, *pos, **kw)
        manifest.update(state='RUNNING', started_at=now())
        save(output/'manifest.json', manifest)
        with patch.object(Page, 'wait_for_function', login_then_wait), \
                patch.object(run_e2e, 'reserve', remember), patch.object(run_e2e, 'report', precheck_report):
            for index, rate in enumerate((3, 5)):
                current.clear()
                print(f'LOCAL_PRECHECK_START rate={rate}', flush=True)
                code = run_e2e.main(['--execute', '--rate', str(rate), '--round', str(args.start_round+index),
                                    '--confirm-ip-policy', '--login-timeout', '60'])
                metric_path = current['output']/'metrics.json'
                metrics = json.loads(metric_path.read_text(encoding='utf-8'))
                row = dict(id=current['id'], rate=rate, code=code, verdict=metrics['verdict'],
                    report=str(current['report'].relative_to(ROOT)), output=str(current['output'].relative_to(ROOT)),
                    metrics_sha256=hashlib.sha256(metric_path.read_bytes()).hexdigest(), counts=metrics.get('counts'))
                results.append(row)
                save(output/'results.json', results)
                if code != 0 or row['verdict'] != 'PASS':
                    manifest['state'] = 'STOPPED_BEFORE_RATE_INCREASE'
                    break
            else:
                manifest['state'] = 'COMPLETED'
    except (Exception, KeyboardInterrupt) as error:
        manifest.update(state='ABORTED', error_type=type(error).__name__)
        # 자격 증명이 포함될 수 있는 예외의 원문은 보존하지 않는다.
    finally:
        username, password = None, None
        manifest.update(ended_at=now(), runs=results)
        verdict = ('FAIL' if any(r['verdict']=='FAIL' for r in results) else
                   'PASS' if manifest['state']=='COMPLETED' and len(results)==2 else 'INCONCLUSIVE')
        manifest['verdict'] = verdict
        save(output/'manifest.json', manifest)
        body = plan.replace('상태: PLANNED / 판정: NOT_EVALUATED', f"상태: {manifest['state']} / 판정: {verdict}")
        body += '\n## 실제 실행 결과\n\n| 요청률 | 실험 ID | 회차 판정 |\n| --- | --- | --- |\n'
        body += '\n'.join(f"| {r['rate']}RPS | {r['id']} | {r['verdict']} |" for r in results)
        body += '\n\n부하별 한 회차의 예비 결과다. 정식 3회 단계 판정은 수행하지 않았다. 비밀번호·세션 파일을 보존하지 않았다.\n'
        report.write_text(body, encoding='utf-8')
        print('LOCAL_PRECHECK_FINISHED', verdict, str(report), flush=True)
    return 0 if manifest['verdict']=='PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
