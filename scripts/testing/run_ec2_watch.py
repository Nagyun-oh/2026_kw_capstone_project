"""P5 시계·자원·중단 장치의 읽기 전용 연결 확인. 부하·장애를 주입하지 않는다."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import time

from ec2_watch import WatchSession,Ec2Guard,calibrate,generator_snapshot,load_observation_policy
from e2e_remote import SSHSettings,HERE
from run_ec2_collection import local_git_state
from run_experiment import ROOT,KST,now,reserve,save,format_record_time


def combined_sample(session,*,clock_status=False):
    exchange=session.exchange('sample',include_clock_status=clock_status)
    remote=exchange['sample']
    if (remote.get('missing_services') or not remote.get('commands')
            or any(c.get('status')!='OK' for c in remote['commands'])):
        raise RuntimeError('SERVER_SAMPLE_INCOMPLETE')
    return dict(at=now(),generator=generator_snapshot(),server=remote['host'],containers=remote['containers'],
        commands=remote['commands'],roundtrip_ms=exchange['roundtrip_ms'],
        ntp_synced=remote.get('ntp_synced'),chrony=remote.get('chrony'))


def report(manifest,clock,samples,guard):
    lines=[f"# 실험 기록: {format_record_time(manifest['planned_at']).split()[0]} — P5 시계·자원 관측", '',
        '[EC2 목차](../README.md) · [P5 가이드](../P5.md)', '', '## 실행 정보',
        f"- ID: `{manifest['id']}`",f"- 상태: {manifest['state']} / {manifest['observation_status']}",
        '- 성능 판정: NOT_EVALUATED',f"- 원본: `build/test-runs/{manifest['id']}/`",
        f"- 시작 / 종료: {format_record_time(manifest.get('started_at'))} / {format_record_time(manifest.get('ended_at'))}",
        '## S — Situation','- PC 발생기와 EC2 서버의 자원·시계를 분리 관측한다.',
        '## T — Task','- 시계 오프셋 구간과 자원 감시를 연결하고 부하 없이 시작 조건을 확인한다.',
        '## T — Target','- 양쪽 메모리, CPU, EC2 steal, 컨테이너 상태·OOM·재시작을 관측한다.',
        '- P1 제안: 시작 여유 각 2GiB, 1GiB 미만 15초 지속·관측 15초 단절·수집 연속 2회 실패 시 중단 판단.',
        '- 종료·OOM·재시작·교체 감지 시 중단. CPU 임계값과 성능 SLO는 P8 확정 전 미설정.',
        '## A — Action','- 기존 검증 호스트 키의 SSH 단일 세션으로 시각 교환·읽기 전용 자원 조회.',
        '- 앱 HTTP·부하·장애 주입·시간 설정·서비스 변경 없음.',
        '## R — Result',f'- 실제 자원 표본: {len(samples)}개.']
    if clock:
        lines += [f"- 서버−PC 오프셋 구간(ms): [{clock['offset_lower_ms']:.3f}, {clock['offset_upper_ms']:.3f}]",
            f"- 구간 폭: {clock['uncertainty_width_ms']:.3f}ms, 시각 교환 {clock['samples']}개."]
    else: lines += ['- 시계 보정: 미확인']
    lines += ['','| 표본 | PC 여유 메모리(GiB) | EC2 여유 메모리(GiB) | PC CPU(%) | EC2 CPU(%) | EC2 steal(%) |',
        '| --- | --- | --- | --- | --- | --- |']
    for i,row in enumerate(samples,1):
        cpu=row.get('cpu_interval',{})
        def number(role,key):
            v=(cpu.get(role) or {}).get(key)
            return '미측정' if v is None else f'{v:.3f}'
        lines.append(f"| {i} | {row['generator']['memory']['available_bytes']/1024**3:.3f} | {row['server']['memory']['available_bytes']/1024**3:.3f} | {number('generator','busy_percent')} | {number('server','busy_percent')} | {number('server','steal_percent')} |")
    lines += ['',f'- 중단 판단: {guard.abort if guard.abort else "관측 중 중단 사유 없음"}',
        '## T — Trouble·복구 확인','- 메모리 부족·OOM·재시작 장애를 실제로 만들지 않았다. 중단 동작은 모의·소유한 임시 프로세스로 검증한다.',
        '- CPU 크레딧 최신값은 이번에 조회하지 않았다. P0 콘솔 자료는 과거 시각이며 부하 직전 재확인해야 한다.',
        '- 새 기준으로 성능 합격을 판정하지 않는다. P6~P8과 실제 부하 중 감시 연결은 아직 남아 있다.',
        '- 서버·PC 시간이나 앱 설정을 변경하지 않았고 소유한 SSH 세션만 종료했다.']
    return '\n'.join(lines)+'\n'


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run',action='store_true')
    mode.add_argument('--check-only',action='store_true')
    p.add_argument('--ssh-host')
    p.add_argument('--identity-file',type=Path)
    p.add_argument('--host-key-alias')
    p.add_argument('--round',type=int,default=1)
    p.add_argument('--samples',type=int,default=5)
    args=p.parse_args(argv)
    if not 1<=args.round<=99 or not 3<=args.samples<=8: p.error('회차 1~99, 자원 표본 3~8개를 지원합니다.')
    policy,digest=load_observation_policy()
    run_id=datetime.now(KST).strftime('%Y%m%dT%H%M%S%z')+f'-ec2-watch-r{args.round:02d}'
    manifest=dict(id=run_id,environment='ec2',schema='ec2-watch-check-v1',state='PLANNED',
        planned_at=now(),observation_status='NOT_COLLECTED',performance_verdict='NOT_EVALUATED',
        samples=args.samples,load_generated=False,server_changes=False,policy_sha256=digest,
        policy_status=policy['status'],credit_observation='NOT_SAMPLED_P0_CONSOLE_REFERENCE_ONLY')
    if args.dry_run:
        print(json.dumps(manifest,ensure_ascii=False,indent=2))
        return 0
    try:
        if not args.ssh_host or not args.identity_file or not args.identity_file.is_file(): raise ValueError('기존 호스트와 키 파일을 확인하세요.')
        settings=SSHSettings(args.ssh_host,args.identity_file,args.host_key_alias)
    except ValueError as error: p.error(str(error))
    output,path=reserve(ROOT,run_id,'ec2')
    manifest.update(local_git_state(),state='RUNNING',started_at=now())
    manifest['source_sha256']={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
        ('ec2_watch.py','ec2_watch_worker.py','ec2_collection_worker.py','run_ec2_watch.py','guard.py')}
    save(output/'manifest.json',manifest)
    clock=None
    samples=[]
    guard=Ec2Guard(policy)
    path.write_text(report(manifest,clock,samples,guard),encoding='utf-8')
    session=WatchSession(settings)
    exchanges=[]
    try:
        session.start()
        for i in range(policy['clock_samples']):
            exchanges.append(session.exchange('clock'))
        clock=calibrate(exchanges)
        save(output/'clock.json',dict(calibration=clock,exchanges=exchanges))
        baseline=combined_sample(session,clock_status=True)
        samples.append(baseline)
        save(output/'sample-01.json',baseline)
        if baseline['ntp_synced'] is not True:
            guard.rules.trip('server_ntp','EC2 NTP 동기화 미확인','INCONCLUSIVE',{})
        if guard.preflight(baseline) and not guard.abort:
            for i in range(1,args.samples):
                time.sleep(policy['stop']['resource_interval_seconds'])
                sample=combined_sample(session)
                guard.observe(sample)
                samples.append(sample)
                save(output/f'sample-{i+1:02d}.json',sample)
                if guard.abort: break
        manifest.update(state='COMPLETED',observation_status='BLOCKED' if guard.abort else 'COLLECTED')
    except KeyboardInterrupt:
        manifest.update(state='INTERRUPTED',observation_status='INCOMPLETE')
    except Exception as error:
        manifest.update(state='FAILED',observation_status='INCOMPLETE',error_code=type(error).__name__)
    finally:
        session.close()
        if exchanges and not (output/'clock.json').exists(): save(output/'clock.json',dict(calibration=clock,exchanges=exchanges))
        manifest.update(ended_at=now(),guard_abort=guard.abort)
        save(output/'manifest.json',manifest)
        save(output/'summary.json',dict(observation_status=manifest['observation_status'],guard_abort=guard.abort,
            resource_samples=len(samples),clock=clock,performance_verdict='NOT_EVALUATED'))
        path.write_text(report(manifest,clock,samples,guard),encoding='utf-8')
    print('관측: '+manifest['observation_status'])
    print('보고서: '+str(path))
    return 0 if manifest['observation_status']=='COLLECTED' else 1


if __name__=='__main__':
    raise SystemExit(main())
