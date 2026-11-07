"""P6 DB 관측의 읽기 전용 전후 수집. 부하·통계 초기화·스키마 변경은 하지 않는다."""
import argparse
import getpass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
import time

from ec2_db import SSHDatabase,compare,section_rows
from ec2_db_queries import queries
from e2e_remote import SSHSettings,HERE
from run_ec2_collection import local_git_state
from run_experiment import ROOT,KST,now,reserve,save,format_record_time


def report(manifest,snapshots,comparison):
    lines=[f"# 실험 기록: {format_record_time(manifest['planned_at']).split()[0]} — P6 DB 관측 연결 확인",'',
        '[EC2 목차](../README.md) · [P6 가이드](../P6.md)', '', '## 실행 정보',
        f"- ID: `{manifest['id']}`",f"- 실행 상태: {manifest['state']}",
        f"- 수집 상태: {manifest['collection_status']}",'- 성능 판정: NOT_EVALUATED',
        f"- 시작 / 종료: {format_record_time(manifest.get('started_at'))} / {format_record_time(manifest.get('ended_at'))}",
        f"- 원본: `build/test-runs/{manifest['id']}/`",f"- outbox 범위 run ID: {manifest['observation_run_id'] or '전체 outbox'}",'',
        '## S — Situation','- 부하 실험 전에 DB 누적 계수·락·트랜잭션·outbox 관측 경로를 확인한다.',
        '## T — Task','- 전후 스냅샷과 조회 자체의 비용을 보존하고 누적 값의 차이를 검증한다.',
        '## T — Target','- 미조회·권한 부족·초기화·행 소실·상한 초과를 0이나 정상 성능으로 처리하지 않는다.',
        '- SELECT 읽기 전용·시간 제한·허용 필드 사용. 설정·권한·DDL·DML·통계 초기화 없음.',
        '## A — Action',('- SSH 앱 계정 조회 후 필요한 항목은 사용자 숨김 입력의 기존 root 인증으로 읽기 전용 재시도.'
            if manifest.get('root_authentication')=='prompt_memory' else
            '- SSH 앱 계정 조회 후 필요한 항목은 컨테이너의 기존 root 인증으로 읽기 전용 재시도.'),
        '- SQL 원문·digest text·요청 본문·잠금 데이터·접속 정보는 저장하지 않는다.',
        '## R — Result','| 표본 | 수집 상태 | digest 행 | outbox 상태 | SSH 수집(ms) |',
        '| --- | --- | --- | --- | --- |']
    for i,row in enumerate(snapshots,1):
        digests=section_rows(row,'digests')
        outbox=section_rows(row,'outbox')
        counts={r['state']:r['count'] for r in outbox} if outbox is not None else '미확인'
        lines.append(f"| {i} | {row['collection_status']} | {len(digests) if digests is not None else '미확인'} | {counts} | {row['transport']['elapsed_ms']:.3f} |")
    if comparison:
        lines += ['',f"- 누적 계수 비교 상태: {comparison['comparison_status']}",
            f"- outbox 발행 지연 집계 차이: {comparison['outbox_publication']}",
            '| digest | 종류·테이블 | 관측기 후보 | 실행 수 차이 | 누적 실행 시간 차이(ms) | 구간 평균(ms) |',
            '| --- | --- | --- | --- | --- | --- |']
        for row in comparison['digest_delta'][:10]:
            delta=row.get('delta')
            if delta is None: continue
            lines.append(f"| {row['digest'][:12]}… | {row['verb']} / {','.join(row['tables'])} | {row['observer_candidate']} | {delta['count']} | {row['total_ms']:.3f} | {row['mean_ms'] if row['mean_ms'] is not None else '미측정'} |")
    lines += ['', '## T — Trouble·복구 확인',
        '- 이 회차는 부하 없는 수집 확인이다. digest·전역 상태에는 앱의 배경 조회와 관측기 자체의 쿼리도 포함된다.',
        '- digest 비교 시간은 전체 기간 평균의 차이가 아니라 SUM_TIMER_WAIT 차이를 COUNT_STAR 차이로 나눈 값이다. p95·p99는 계산하지 않는다.',
        '- PROCESS·Performance Schema 권한이 없으면 미확인으로 보존한다. 권한 추가·계측 활성화·카운터 초기화는 수행하지 않는다.',
        '- outbox 발행 시각은 저장소가 UTC_TIMESTAMP로 기록한 DB 시각끼리 비교한다. 다른 로그의 DATETIME을 보정하지 않는다.',
        '- 테이블 행 수는 information_schema 추정치다. 락·장기 트랜잭션은 조회 순간의 표본이며 부재가 전체 구간의 무경합을 증명하지 않는다.',
        '- 서비스·설정·데이터 변경 없음. 수집 명령 시간과 원본을 보존했으며 성능 판단은 본 실험에서 진행한다.']
    return '\n'.join(lines)+'\n'


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run',action='store_true')
    mode.add_argument('--collect-only',action='store_true')
    p.add_argument('--ssh-host')
    p.add_argument('--identity-file',type=Path)
    p.add_argument('--host-key-alias')
    p.add_argument('--run-id')
    p.add_argument('--app-only',action='store_true',help='기존 root 인증의 읽기 전용 재시도도 사용하지 않음')
    p.add_argument('--prompt-db-root',action='store_true',help='기존 root 비밀번호를 숨김 입력. SSH·프로세스 표준 입력으로만 전달하며 저장하지 않음')
    p.add_argument('--round',type=int,default=1)
    p.add_argument('--interval',type=int,default=5)
    args=p.parse_args(argv)
    if not 1<=args.round<=99 or not 5<=args.interval<=30: p.error('회차 1~99, 전후 대기 5~30초만 지원합니다.')
    if args.prompt_db_root and args.app_only: p.error('--app-only와 --prompt-db-root는 함께 사용할 수 없습니다.')
    try: queries(args.run_id)
    except ValueError as error: p.error(str(error))
    run_id=datetime.now(KST).strftime('%Y%m%dT%H%M%S%z')+f'-ec2-db-observation-r{args.round:02d}'
    manifest=dict(id=run_id,schema='ec2-db-observation-check-v1',environment='ec2',state='PLANNED',
        planned_at=now(),collection_status='NOT_COLLECTED',performance_verdict='NOT_EVALUATED',
        observation_run_id=args.run_id,allow_existing_root_read_only=not args.app_only,
        root_authentication='prompt_memory' if args.prompt_db_root else 'container_environment',
        interval_after_collection_seconds=args.interval,load_generated=False,server_changes=False)
    if args.dry_run:
        print(json.dumps(manifest,ensure_ascii=False,indent=2))
        return 0
    try:
        if not args.ssh_host or not args.identity_file or not args.identity_file.is_file(): raise ValueError('기존 SSH 호스트와 키를 확인하세요.')
        settings=SSHSettings(args.ssh_host,args.identity_file,args.host_key_alias)
    except ValueError as error: p.error(str(error))
    if args.prompt_db_root and not sys.stdin.isatty():
        p.error('숨김 입력은 직접 열린 로컬 터미널에서 실행하세요. 비밀번호를 파이프로 전달하지 마세요.')
    root_password=getpass.getpass('MySQL root password (hidden): ') if args.prompt_db_root else None
    output,path=reserve(ROOT,run_id,'ec2')
    manifest.update(local_git_state(),state='RUNNING',started_at=now())
    manifest['source_sha256']={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
        ('ec2_db.py','ec2_db_queries.py','ec2_db_worker.py','ec2_collection_worker.py','run_ec2_db.py')}
    save(output/'manifest.json',manifest)
    snapshots=[]
    comparison=None
    path.write_text(report(manifest,snapshots,comparison),encoding='utf-8')
    collector=SSHDatabase(settings)
    try:
        for i in range(2):
            value=collector.collect(args.run_id,allow_root=not args.app_only,root_password=root_password)
            snapshots.append(value)
            save(output/f'snapshot-{i+1:02d}.json',value)
            if i==0: time.sleep(args.interval)
        comparison=compare(*snapshots)
        save(output/'comparison.json',comparison)
        manifest.update(state='COMPLETED',collection_status='COLLECTED' if all(
            r['collection_status']=='COLLECTED' for r in snapshots) and comparison['comparison_status']=='COMPARABLE' else 'INCOMPLETE')
    except KeyboardInterrupt: manifest.update(state='INTERRUPTED',collection_status='INCOMPLETE')
    except Exception as error: manifest.update(state='FAILED',collection_status='INCOMPLETE',error_code=type(error).__name__)
    finally:
        manifest['ended_at']=now()
        save(output/'manifest.json',manifest)
        path.write_text(report(manifest,snapshots,comparison),encoding='utf-8')
    print('DB 수집: '+manifest['collection_status'])
    print('보고서: '+str(path))
    return 0 if manifest['collection_status']=='COLLECTED' else 1


if __name__=='__main__': raise SystemExit(main())
