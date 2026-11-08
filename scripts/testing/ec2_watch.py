"""P5 시계 구간 보정·발생기/서버 자원 감시·실험 중단 판단. 앱 상태는 바꾸지 않는다."""
from datetime import datetime,timezone
import base64
import ctypes
import hashlib
import json
import math
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

from e2e_remote import HERE,now
from guard import host_memory,valid_memory,StopRules,stop_load

PROFILE=HERE/'profiles/ec2-observation-v1.json'
BOOTSTRAP="python3 -u -c 'import sys,base64;exec(base64.b64decode(sys.stdin.buffer.readline()))'"


def epoch_ms():
    """Windows Python 3.12의 거친 time.time 갱신 대신 정밀 UTC 시각을 읽는다."""
    if sys.platform=='win32':
        stamp=ctypes.c_ulonglong()
        api=ctypes.WinDLL('kernel32',use_last_error=True).GetSystemTimePreciseAsFileTime
        api.argtypes=[ctypes.POINTER(ctypes.c_ulonglong)]
        api.restype=None
        api(ctypes.byref(stamp))
        return (stamp.value-116444736000000000)/10000
    return time.time_ns()/1_000_000


def load_observation_policy():
    raw=PROFILE.read_bytes()
    value=json.loads(raw)
    if value.get('version')!='ec2-observation-v1' or value.get('status')!='P5_GUARD_IMPLEMENTED_P8_CONFIRMATION_PENDING':
        raise ValueError('EC2 관측 기준 버전 오류')
    for key in ('start_available_memory_bytes','max_sample_gap_seconds','clock_samples','clock_max_age_seconds'):
        if type(value.get(key)) not in (int,float) or not math.isfinite(value[key]) or value[key]<=0:
            raise ValueError('관측 기준 수치 오류')
    for v in value.get('stop',{}).values():
        if type(v) not in (int,float) or not math.isfinite(v) or v<=0:
            raise ValueError('중단 기준 수치 오류')
    return value,hashlib.sha256(raw).hexdigest()


class WatchSession:
    """한 SSH 세션에서 여러 교환을 수행해 매 표본의 접속 초기화 비용을 분리한다."""
    def __init__(self,settings,popen=None):
        self.settings,self.popen=settings,popen or subprocess.Popen
        self.process=None
        self.sequence=0
        self.responses=queue.Queue(maxsize=8)
        self.reader=None
        self.lock=threading.Lock()

    def start(self):
        source=(HERE/'ec2_collection_worker.py').read_text(encoding='utf-8')+'\n'+(HERE/'ec2_watch_worker.py').read_text(encoding='utf-8')+'\nwatch_main()\n'
        self.process=self.popen(self.settings.argv()[:-1]+[BOOTSTRAP],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        def read():
            try:
                while True:
                    line=self.process.stdout.readline(2*1024*1024+1)
                    if not line or len(line)>2*1024*1024:
                        self.responses.put(None,timeout=1)
                        return
                    self.responses.put(line,timeout=1)
            except (OSError,ValueError,queue.Full):
                return
        self.reader=threading.Thread(target=read,daemon=True)
        self.reader.start()
        self.process.stdin.write(base64.b64encode(source.encode('utf-8'))+b'\n')
        self.process.stdin.flush()
        return self

    def exchange(self,op,*,include_clock_status=False,timeout=12):
        with self.lock:
            self.sequence+=1
            payload=dict(op=op,sequence=self.sequence,include_clock_status=include_clock_status)
            t0=epoch_ms()
            mono=time.perf_counter()
            try:
                self.process.stdin.write(json.dumps(payload).encode('utf-8')+b'\n')
                self.process.stdin.flush()
                raw=self.responses.get(timeout=timeout)
                t3=epoch_ms()
                elapsed=(time.perf_counter()-mono)*1000
                if raw is None:
                    raise ValueError('SSH_CLOSED')
                response=json.loads(raw)
                if (response.get('schema')!='dualguard-ec2-watch-v1' or response.get('op')!=op
                        or response.get('sequence')!=self.sequence or response.get('error')):
                    raise ValueError('INVALID_WATCH_RESPONSE')
                result=dict(client_sent_ms=t0,client_received_ms=t3,roundtrip_ms=elapsed,
                    server_received_ms=response['server_received_ms'],server_sent_ms=response['server_sent_ms'],
                    observed_monotonic=time.perf_counter(),at=now())
                if op=='sample': result['sample']=response['sample']
                return result
            except (OSError,ValueError,TypeError,KeyError,queue.Empty):
                # 늦은 응답과 다음 요청이 섞이지 않도록 실패한 세션은 닫는다.
                self.close()
                raise RuntimeError('SSH_WATCH_FAILED') from None

    def close(self):
        proc=self.process
        if proc is None: return
        if proc.poll() is None:
            try:
                proc.stdin.write(b'{"op":"quit"}\n')
                proc.stdin.flush()
                proc.wait(timeout=2)
            except (OSError,ValueError,subprocess.TimeoutExpired):
                proc.terminate()
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
        for stream in (proc.stdin,proc.stdout):
            if stream and not stream.closed: stream.close()
        if self.reader and self.reader is not threading.current_thread(): self.reader.join(timeout=2)


def calibrate(exchanges):
    intervals=[]
    for row in exchanges:
        keys=('client_sent_ms','client_received_ms','server_received_ms','server_sent_ms','roundtrip_ms')
        if any(type(row.get(k)) not in (int,float) or not math.isfinite(row[k]) for k in keys):
            raise ValueError('시계 표본 형식 오류')
        c0,c3,s1,s2,rtt=(row[k] for k in keys)
        if c3<c0 or s2<s1 or rtt<0 or abs((c3-c0)-rtt)>10:
            raise ValueError('관측 중 시계 점프 또는 시각 순서 오류')
        lower,upper=s2-c3-1,s1-c0+1
        if lower>upper:
            raise ValueError('시계 구간 산출 불가')
        intervals.append((lower,upper))
    if len(intervals)<3:
        raise ValueError('시계 보정 표본이 3개 미만입니다.')
    lower=max(r[0] for r in intervals)
    upper=min(r[1] for r in intervals)
    if lower>upper:
        raise ValueError('시계 보정 구간이 일치하지 않습니다.')
    return dict(offset_lower_ms=lower,offset_upper_ms=upper,uncertainty_width_ms=upper-lower,
        samples=len(intervals),calibrated_at=now(),observed_monotonic=exchanges[-1]['observed_monotonic'],
        generator_reference_ms=exchanges[-1]['client_received_ms'],
        direction='server_epoch_minus_generator_epoch',method='four_timestamp_offset_interval',resolution_margin_ms=1)


def clock_window_excess(start_ms,sent_ms,ended_ms,clock,*,monotonic=None,max_age=300,
                        ingress_resolution_ms=0,client_resolution_ms=0):
    """WAF 시작 시각이 보정 구간(송신~수신 + 오프셋 구간)을 벗어난 크기(ms). 0 이하면 구간 안이다.

    값이 유효하지 않거나 보정이 오래돼 판단할 수 없으면 None이다.
    """
    if not all(type(v) in (int,float) and math.isfinite(v) for v in (start_ms,sent_ms,ended_ms)):
        return None
    current=time.perf_counter() if monotonic is None else monotonic
    if current-clock['observed_monotonic']<0 or current-clock['observed_monotonic']>max_age:
        return None
    if ingress_resolution_ms not in (0,1) or client_resolution_ms not in (0,1):
        return None
    # 각 필드의 실제 1ms 해상도를 가능한 시각 구간으로 전파한다.
    # Nginx 시작 시각은 ms 값의 차이, k6 Date.now()는 정수 ms다.
    return max((sent_ms+clock['offset_lower_ms'])-(start_ms+ingress_resolution_ms),
               (start_ms-ingress_resolution_ms)-(ended_ms+client_resolution_ms+clock['offset_upper_ms']))


def ingress_in_clock_interval(start_ms,sent_ms,ended_ms,clock,**options):
    excess=clock_window_excess(start_ms,sent_ms,ended_ms,clock,**options)
    return excess is not None and excess<=0


def generator_snapshot():
    if sys.platform=='win32':
        from ctypes import wintypes
        idle,kernel,user=wintypes.FILETIME(),wintypes.FILETIME(),wintypes.FILETIME()
        api=ctypes.WinDLL('kernel32',use_last_error=True).GetSystemTimes
        api.argtypes=[ctypes.POINTER(wintypes.FILETIME)]*3
        api.restype=wintypes.BOOL
        if not api(ctypes.byref(idle),ctypes.byref(kernel),ctypes.byref(user)):
            raise ctypes.WinError(ctypes.get_last_error())
        value=lambda f:(f.dwHighDateTime<<32)+f.dwLowDateTime
        cpu=dict(total=value(kernel)+value(user),idle=value(idle))
    elif sys.platform.startswith('linux'):
        nums=list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
        cpu=dict(total=sum(nums),idle=nums[3]+nums[4])
    else:
        raise RuntimeError('발생기 CPU 수집을 지원하지 않는 OS')
    return dict(at=now(),monotonic=time.perf_counter(),memory=host_memory(),cpu=cpu)


def cpu_percent(before,after,*,linux=False):
    if before is None: return None
    if linux:
        total=sum(after.values())-sum(before.values())
        idle=after['idle']+after['iowait']-before['idle']-before['iowait']
        steal=after['steal']-before['steal']
    else:
        total=after['total']-before['total']
        idle=after['idle']-before['idle']
        steal=None
    if total<=0 or idle<0 or idle>total or (steal is not None and not 0<=steal<=total):
        raise ValueError('CPU 누적 계수 초기화·형식 오류')
    return dict(busy_percent=(total-idle)/total*100,steal_percent=None if steal is None else steal/total*100)


class Ec2Guard:
    def __init__(self,policy,*,stopper=None,sample_provider=None):
        self.policy=policy
        self.rules=StopRules(policy)
        self.baseline=None
        self.low_since={}
        self.latest=None
        self.previous=None
        self.owned_load=None
        self.stopper=stopper or stop_load
        self.stopped=False
        self.sample_provider=sample_provider
        self.last_sample=None

    @property
    def abort(self): return self.rules.abort

    def attach_owned_load(self,process):
        if self.owned_load is not None and self.owned_load.poll() is None:
            raise ValueError('이미 실행 중인 소유 부하가 등록돼 있습니다.')
        self.owned_load=process
        self.stopped=False

    def apply_stop(self):
        if self.abort and self.owned_load is not None and not self.stopped:
            self.stopper(self.owned_load)
            self.stopped=True

    def collected(self,name,success):
        self.rules.collected(name,success)
        self.apply_stop()

    def validate(self,sample):
        for role in ('generator','server'):
            if not valid_memory(sample[role]['memory']): raise ValueError('메모리 표본 오류')
            if not math.isfinite(sample[role]['monotonic']): raise ValueError('관측 시각 오류')
        states=sample['containers']
        if len(states)!=len(self.policy['required_services']) or {r['service'] for r in states}!=set(self.policy['required_services']):
            raise ValueError('필수 컨테이너 누락')
        for row in states:
            if (type(row.get('running')) is not bool or type(row.get('oom_killed')) is not bool
                    or type(row.get('restart_count')) is not int or row['restart_count']<0
                    or not row.get('id') or not row.get('started_at')):
                raise ValueError('컨테이너 상태 형식 오류')

    def preflight(self,sample):
        self.validate(sample)
        self.baseline=sample
        self.latest=time.perf_counter()
        for role in ('generator','server'):
            if sample[role]['memory']['available_bytes']<self.policy['start_available_memory_bytes']:
                self.rules.trip(role+'_start_memory','시작 전 '+role+' 여유 메모리 기준 미충족','INCONCLUSIVE',sample[role]['memory'])
        for r in sample['containers']:
            if not r['running'] or r['oom_killed'] or r.get('health')=='unhealthy':
                self.rules.trip('container_preflight','시작 전 컨테이너 상태 미충족','FAIL',dict(service=r['service']))
        self.previous=sample
        self.apply_stop()
        return self.abort is None

    def observe(self,sample,*,observed=None):
        observed=time.perf_counter() if observed is None else observed
        try:
            self.validate(sample)
            if self.latest is not None and observed-self.latest>self.policy['max_sample_gap_seconds']:
                self.low_since={}
                self.rules.trip('resource_gap','자원 관측 간격이 허용치를 초과했습니다.','INCONCLUSIVE',dict(gap_seconds=observed-self.latest))
            for role in ('generator','server'):
                point=sample[role]
                stamp=point['monotonic']
                if point['memory']['available_bytes']>=self.policy['stop']['min_available_memory_bytes']:
                    self.low_since.pop(role,None)
                else:
                    self.low_since.setdefault(role,stamp)
                    if stamp-self.low_since[role]>=self.policy['stop']['low_memory_seconds']:
                        self.rules.trip(role+'_low_memory',role+' 여유 메모리 부족이 지속됐습니다.','INCONCLUSIVE',point['memory'])
            before={r['service']:r for r in self.baseline['containers']}
            for row in sample['containers']:
                old=before[row['service']]
                if (not row['running'] or row['oom_killed'] or row.get('health')=='unhealthy'
                        or any(row[k]!=old[k] for k in ('id','started_at','restart_count'))):
                    self.rules.trip('container_state','필수 컨테이너 종료·OOM·재시작·교체 감지','FAIL',dict(service=row['service']))
            if sample['server']['boot_sha256']!=self.baseline['server']['boot_sha256']:
                self.rules.trip('server_reboot','EC2 재부팅 감지','FAIL',{})
            sample['cpu_interval']={role:cpu_percent(self.previous[role]['cpu'],sample[role]['cpu'],linux=role=='server')
                                    for role in ('generator','server')}
            self.collected('ec2_resources',True)
            self.latest=observed
            self.previous=sample
        except (ValueError,KeyError,TypeError):
            self.low_since={}
            self.collected('ec2_resources',False)
        self.apply_stop()
        return self.abort

    def resources(self):
        if self.sample_provider is None:
            raise RuntimeError('EC2 자원 관측 제공자가 필요합니다.')
        try:
            sample=self.sample_provider()
            self.observe(sample)
            self.last_sample=sample
            return sample
        except Exception:
            self.low_since={}
            self.collected('ec2_resources',False)
            return None

    def watchdog(self,observed=None):
        current=time.perf_counter() if observed is None else observed
        if self.latest is not None and current-self.latest>self.policy['max_sample_gap_seconds']:
            self.rules.trip('resource_stale','자원 감시 응답이 오래 끊겼습니다.','INCONCLUSIVE',{})
        self.apply_stop()
