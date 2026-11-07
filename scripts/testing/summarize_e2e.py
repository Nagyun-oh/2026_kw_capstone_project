"""동일 조건 v2 회차 3개의 단계 판정. 원본 지연 표본을 합산한다."""
import argparse
import hashlib
import json
import math
from pathlib import Path
from pipeline import distribution
from run_experiment import ROOT, now, format_record_time


def summarize(paths):
    if len(paths) != 3 or len({Path(p).resolve() for p in paths}) != 3:
        raise ValueError('서로 다른 회차 3개가 필요합니다.')
    runs, keys, pooled = [], [], {}
    for path in paths:
        path = Path(path)
        manifest = json.loads((path/'manifest.json').read_text(encoding='utf-8'))
        metrics = json.loads((path/'metrics.json').read_text(encoding='utf-8'))
        if (manifest.get('schema') != 'local-e2e-v2' or manifest.get('connection_check')
                or manifest.get('environment', 'local') != 'local'):
            raise ValueError('본 측정 v2 회차만 합산할 수 있습니다.')
        if any(manifest.get(k) is None for k in ('rate', 'seconds', 'warmup_seconds', 'fixture_sha256',
                  'contract_sha256', 'runner_files_sha256', 'app_sources_sha256', 'versions', 'images')):
            raise ValueError('회차 비교 조건 누락')
        if metrics.get('verdict') not in {'PASS', 'FAIL', 'INCONCLUSIVE'}:
            raise ValueError('판정 누락')
        if metrics['verdict'] == 'PASS' and (manifest.get('state') != 'COMPLETED' or not metrics.get('latency_samples_ms')):
            raise ValueError('완료 상태·원본 지연 표본 없는 PASS')
        keys.append({k: manifest.get(k) for k in ('rate', 'seconds', 'warmup_seconds',
            'fixture_sha256', 'contract_sha256', 'runner_files_sha256', 'app_sources_sha256',
            'ip_policy_confirmed', 'versions')})
        keys[-1]['image_digests'] = sorted(row.split()[-1] for row in manifest.get('images', []))
        keys[-1].update(environment=manifest.get('environment', 'local'),
                        target_url=manifest.get('target_url', 'http://localhost/'),
                        dashboard_url=manifest.get('dashboard_url', 'http://localhost:3000/'))
        for name, values in metrics.get('latency_samples_ms', {}).items():
            if not isinstance(values, list) or any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
                raise ValueError('합산 원본 지연 표본 형식 오류')
            pooled.setdefault(name, []).extend(values)
        runs.append(dict(id=manifest['id'], verdict=metrics['verdict'],
                         metrics_sha256=hashlib.sha256((path/'metrics.json').read_bytes()).hexdigest(),
                         db_start_counts=manifest.get('db_start_counts')))
    if any(k != keys[0] for k in keys[1:]):
        raise ValueError('부하·fixture·코드·이미지·계약 조건이 다른 회차를 합칠 수 없습니다.')
    verdicts = {r['verdict'] for r in runs}
    verdict = 'FAIL' if 'FAIL' in verdicts else 'PASS' if verdicts == {'PASS'} else 'INCONCLUSIVE'
    return dict(at=now(), verdict=verdict, runs=runs, conditions=keys[0],
                pooled_stats_ms={k: distribution(v) for k, v in pooled.items()},
                limits=['p99는 참고값', 'DB 증가·캐시·CPU 크레딧·동시 트래픽은 보고서에서 추가 대조 필요'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', nargs=3, required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if output.suffix != '.md' or not output.is_relative_to(ROOT.resolve()) or output.exists() or output.with_suffix('.json').exists():
        parser.error('프로젝트 안의 새 보고서 경로를 사용해주세요. 기존 파일은 덮어쓰지 않습니다.')
    result = summarize(args.runs)
    output.parent.mkdir(parents=True, exist_ok=True)
    body = f"# 단계 비교: {format_record_time(result['at']).split()[0]} — v2\n\n판정: **{result['verdict']}**\n\n"
    body += '\n'.join(f"- {r['id']}: {r['verdict']}" for r in result['runs'])
    body += '\n\n원본 표본 합산 통계·조건·해시는 같은 이름의 JSON을 참고한다. p99 평균을 사용하지 않는다.\n'
    with output.open('x', encoding='utf-8') as stream:
        stream.write(body)
    with output.with_suffix('.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
