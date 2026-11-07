"""P5 지속 SSH 세션의 시계·호스트 자원·컨테이너 상태 관측. P4 Runner와 함께 전달한다."""
import hashlib
import sys


def host_snapshot():
    fields=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
    cpu=Path('/proc/stat').read_text().splitlines()[0].split()[1:9]
    return dict(memory=dict(total_bytes=int(fields['MemTotal'].split()[0])*1024,
                            available_bytes=int(fields['MemAvailable'].split()[0])*1024,
                            source='Linux /proc/meminfo'),
                cpu=dict(zip(('user','nice','system','idle','iowait','irq','softirq','steal'),map(int,cpu))),
                logical_cpus=os.cpu_count(),monotonic=time.monotonic(),
                boot_sha256=hashlib.sha256(Path('/proc/sys/kernel/random/boot_id').read_bytes()).hexdigest())


def watch_sample(include_clock_status=False):
    runner=Runner()
    ids=discover(runner)
    template='{"id":{{json .Id}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"running":{{.State.Running}},"oom_killed":{{.State.OOMKilled}},"health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}},"restart_count":{{.RestartCount}},"started_at":{{json .State.StartedAt}}}'
    text=runner.run('guard_containers',['sudo','-n','docker','inspect','--format',template,*ids.values()],timeout=5) if ids else None
    states=[json.loads(line) for line in text.splitlines()] if text is not None else None
    data=dict(host=host_snapshot(),containers=states,commands=runner.commands,
              missing_services=sorted(SERVICES-set(ids)))
    if include_clock_status:
        ntp=runner.run('ntp_synced',['timedatectl','show','--property=NTPSynchronized','--value'],timeout=3)
        data['ntp_synced']=True if ntp and ntp.strip()=='yes' else False if ntp and ntp.strip()=='no' else None
        chrony=runner.run('chrony_tracking',['chronyc','tracking'],timeout=3)
        keep={'System time','Last offset','RMS offset','Stratum','Leap status'}
        data['chrony']=[line.strip() for line in chrony.splitlines() if line.split(':',1)[0].strip() in keep] if chrony else None
    return data


def watch_main():
    if os.name!='posix' or not (Path(REPO)/'compose.aws.yaml').is_file():
        raise SystemExit(2)
    for line in sys.stdin:
        received=time.time_ns()/1_000_000
        try:
            request=json.loads(line)
            op=request.get('op')
            if op=='quit':
                return
            if op not in ('clock','sample') or type(request.get('sequence')) is not int:
                raise ValueError('INVALID_OPERATION')
            result=dict(schema='dualguard-ec2-watch-v1',sequence=request['sequence'],op=op,
                        server_received_ms=received)
            if op=='sample':
                result['sample']=watch_sample(request.get('include_clock_status') is True)
            result['server_sent_ms']=time.time_ns()/1_000_000
        except Exception:
            result=dict(schema='dualguard-ec2-watch-v1',error='REMOTE_WATCH_FAILED')
        print(json.dumps(result,separators=(',',':')),flush=True)
