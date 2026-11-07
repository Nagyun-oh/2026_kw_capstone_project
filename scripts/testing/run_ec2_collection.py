"""P4 읽기 전용 SSH 수집 검증. HTTP·부하·브라우저·서비스 변경은 수행하지 않는다."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import time

from e2e_remote import SSHCollection, SSHSettings, worker_request
from metrics import resource_peaks
from pipeline import partition_keys, zero_lag
from run_experiment import ROOT, HERE, KST, now, reserve, save, format_record_time


def report(manifest, snapshots):
    times=[r['transport']['elapsed_ms'] for r in snapshots]
    lines=[f"# 실험 기록: {format_record_time(manifest['planned_at']).split()[0]} — P4 원격 수집 연결 확인", '',
        '[EC2 목차](../README.md) · [P4 가이드](../P4.md)', '',
        '## 실행 정보', f"- ID: `{manifest['id']}`", f"- 실행 상태: {manifest['state']}",
        f"- 수집 판정: {manifest['collection_status']}", '- 성능 판정: NOT_EVALUATED',
        f"- 시작 / 종료: {format_record_time(manifest.get('started_at'))} / {format_record_time(manifest.get('ended_at'))}",
        f"- 관측 대상 run ID: `{manifest['observation_run_id']}`",
        f"- 원본: `build/test-runs/{manifest['id']}/`", '',
        '## S — Situation', '- EC2 부하 실행 전 SSH 수집 경로와 기존 파서 연결을 확인한다.',
        '## T — Task', '- lag·실험 DB 메타데이터·계측 로그·컨테이너 자원과 상태를 읽기 전용으로 수집한다.',
        '## T — Target', '- 수집별 상태·시각·종료 코드·소요 시간을 확보하고 실패·미확인을 0으로 치환하지 않는다.',
        '- 앱 요청·부하·DB 변경·서비스 재시작·WAF 설정 변경을 수행하지 않는다.',
        '## A — Action', f"- 요청한 표본 수: {manifest['samples']}. 실제 표본 수: {len(snapshots)}.",
        '- SSH 표준 입력으로 수집기를 전달했다. 서버 저장소에 파일을 설치하지 않는다.',
        '## R — Result', '| 표본 | 수집 | lag | DB 행 | trace | 자원 표본 | SSH 왕복 수집 시간(ms) |',
        '| --- | --- | --- | --- | --- | --- | --- |']
    for i,row in enumerate(snapshots,1):
        lag=row.get('lag')
        lag_label='미확인' if not lag else ('필수 group 모두 0' if zero_lag(lag,partition_keys(lag)) else '0 아님 또는 불완전')
        count=lambda key:len(row[key]) if row.get(key) is not None else '미확인'
        resources=row.get('resources')
        lines.append(f"| {i} | {row['collection_status']} | {lag_label} | {count('database')} | {count('traces')} | {len(resources['containers']) if resources else '미확인'} | {row['transport']['elapsed_ms']} |")
    lines += ['', '- 관측한 EC2 HEAD: '+str(sorted({r['app_sha'] for r in snapshots if r.get('app_sha')}))]
    lines += ['', f'- SSH 왕복 수집 시간 표본(ms): {times or "미측정"}',
        '- 세부 명령 비용·수집 오류·재시작 횟수·health는 snapshot JSON에 보존한다.',
        '## T — Trouble·복구 확인', '- 빈 DB·trace는 관측 대상 run ID에 일치하는 결과가 없다는 뜻이며 과거 처리 누락을 증명하지 않는다.',
        '- 계측 요청 ID를 별도로 지정했다면 기존 기록의 필터 검증용이며 신규 E2E 측정으로 집계하지 않는다.',
        '- 컨테이너 health가 null이면 healthcheck가 없는 것이며 healthy로 바꾸지 않는다.',
        '- 수집 자체의 비용은 존재한다. 현재 주기·수집 비용이 부하 실험에 적합한지는 P5~P6에서 검토한다.',
        '- 앱·DB·설정 변경 없음. 실패 시 자신이 시작한 SSH·조회만 제한 시간으로 종료한다.']
    return '\n'.join(lines)+'\n'


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run',action='store_true')
    mode.add_argument('--collect-only',action='store_true')
    parser.add_argument('--ssh-host')
    parser.add_argument('--identity-file',type=Path)
    parser.add_argument('--host-key-alias')
    parser.add_argument('--since',required=True,help='로그 조회 시작 ISO 시각')
    parser.add_argument('--run-id',help='DB 대조 대상 기존 실험 ID. 없으면 이번 수집 ID')
    parser.add_argument('--request-id',action='append',default=[],help='기존 계측의 필터 검증용 requestId')
    parser.add_argument('--round',type=int,default=1)
    parser.add_argument('--samples',type=int,default=1)
    parser.add_argument('--interval',type=int,default=5)
    args=parser.parse_args(argv)
    if not 1<=args.round<=99 or not 1<=args.samples<=3 or not 5<=args.interval<=30:
        parser.error('회차 1~99, 표본 1~3, 표본 간격 5~30초만 지원합니다.')
    run_id=datetime.now(KST).strftime('%Y%m%dT%H%M%S%z')+f'-ec2-collection-r{args.round:02d}'
    observation=args.run_id or run_id
    try:
        worker_request(observation,args.since,args.request_id,'check')
        settings=None
        if args.collect_only:
            if not args.ssh_host or not args.identity_file or not args.identity_file.is_file():
                raise ValueError('기존 SSH 호스트와 읽을 수 있는 개인 키 파일이 필요합니다.')
            settings=SSHSettings(args.ssh_host,args.identity_file,args.host_key_alias)
    except ValueError as error:
        parser.error(str(error))
    manifest=dict(id=run_id, schema='ec2-collection-check-v1', environment='ec2', state='PLANNED',
        collection_status='NOT_COLLECTED', performance_verdict='NOT_EVALUATED', planned_at=now(),
        observation_run_id=observation, since=args.since, samples=args.samples, interval_seconds=args.interval,
        explicit_trace_request_ids=args.request_id, load_generated=False, server_changes=False,
        target_alias='ec2-a', generator_alias='generator-a')
    if args.dry_run:
        print(json.dumps(manifest,ensure_ascii=False,indent=2))
        return 0
    output,path=reserve(ROOT,run_id,'ec2')
    source_names=('run_ec2_collection.py','e2e_remote.py','ec2_collection_worker.py','e2e_core.py','metrics.py','pipeline.py')
    manifest['source_sha256']={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in source_names}
    manifest.update(local_git_state())
    manifest.update(state='RUNNING',started_at=now())
    save(output/'manifest.json',manifest)
    path.write_text(report(manifest,[]),encoding='utf-8')
    snapshots=[]
    keys=set()
    collector=SSHCollection(settings)
    try:
        for i in range(args.samples):
            row=collector.collect(observation,args.since,args.request_id,mode='check',expected_keys=keys)
            if row['lag']:
                keys |= partition_keys(row['lag'])
            snapshots.append(row)
            save(output/f'snapshot-{i+1:02d}.json',row)
            if row['collection_status']!='COLLECTED':
                break
            if i+1<args.samples:
                time.sleep(args.interval)
        manifest['state']='COMPLETED'
    except KeyboardInterrupt:
        manifest['state']='INTERRUPTED'
    finally:
        manifest.update(ended_at=now(),collection_status='COLLECTED' if manifest['state']=='COMPLETED'
            and len(snapshots)==args.samples and all(r['collection_status']=='COLLECTED' for r in snapshots) else 'INCOMPLETE')
        save(output/'manifest.json',manifest)
        save(output/'summary.json',dict(collection_status=manifest['collection_status'],
            resource_peaks=resource_peaks([r['resources'] for r in snapshots if r['resources']]),
            collection_elapsed_ms=[r['transport']['elapsed_ms'] for r in snapshots]))
        path.write_text(report(manifest,snapshots),encoding='utf-8')
    print('수집: '+manifest['collection_status'])
    print('보고서: '+str(path))
    return 0 if manifest['collection_status']=='COLLECTED' else 1


def local_git_state():
    import subprocess
    try:
        head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True,timeout=5).strip()
        dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True,timeout=5).strip())
        return dict(runner_head=head,runner_working_tree_dirty=dirty)
    except (OSError,subprocess.SubprocessError):
        return dict(runner_head=None,runner_working_tree_dirty=None)


if __name__=='__main__':
    raise SystemExit(main())
