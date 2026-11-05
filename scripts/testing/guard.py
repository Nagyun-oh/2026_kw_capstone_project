"""성능 실험의 자동 중단 감시. 서비스는 변경하지 않고 중단 사유만 실행기에 전달한다."""
from datetime import datetime, timezone
import json
import math
import sys
import threading
import time

from pipeline import utc_time


def host_memory():
    if sys.platform == "win32":
        import ctypes
        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong) for name in (
                    "total_phys", "available_phys", "total_page", "available_page",
                    "total_virtual", "available_virtual", "available_extended")]
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        query = kernel.GlobalMemoryStatusEx
        query.argtypes = [ctypes.POINTER(MemoryStatus)]
        query.restype = ctypes.c_int
        if not query(ctypes.byref(status)):
            raise ctypes.WinError(ctypes.get_last_error())
        return dict(total_bytes=status.total_phys, available_bytes=status.available_phys,
                    source="Windows GlobalMemoryStatusEx")
    if sys.platform.startswith("linux"):
        from pathlib import Path
        fields = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        return dict(total_bytes=int(fields["MemTotal"].split()[0])*1024,
                    available_bytes=int(fields["MemAvailable"].split()[0])*1024,
                    source="Linux /proc/meminfo")
    raise RuntimeError("호스트 메모리 수집을 지원하지 않는 OS")


def valid_memory(value):
    return (type(value.get("total_bytes")) is int and type(value.get("available_bytes")) is int
            and 0 <= value["available_bytes"] <= value["total_bytes"] and value["total_bytes"] > 0)


class StopRules:
    def __init__(self, policy):
        self.policy = policy
        self.abort = None
        self.failures = {}
        self.low_since = None
        self.window = []
        self.latest_http = None
        self.http_count = 0
        self.lock = threading.RLock()

    def trip(self, code, reason, verdict, evidence):
        with self.lock:
            if self.abort is None:
                self.abort = dict(code=code, reason=reason, verdict=verdict, evidence=evidence,
                                  at=datetime.now(timezone.utc).isoformat())
            elif verdict == "FAIL" and self.abort["verdict"] != "FAIL":
                self.abort = dict(code=code, reason=reason, verdict=verdict, evidence=evidence,
                                  at=datetime.now(timezone.utc).isoformat(), first_stop=self.abort)

    def collected(self, name, success):
        with self.lock:
            self.failures[name] = 0 if success else self.failures.get(name, 0)+1
            if self.failures[name] >= self.policy["stop"]["consecutive_collection_failures"]:
                self.trip("collection_failure", f"필수 수집 {name}이 연속 두 번 실패했습니다.",
                          "INCONCLUSIVE", dict(collector=name, consecutive_failures=self.failures[name]))

    def memory(self, value, monotonic):
        with self.lock:
            if not valid_memory(value):
                self.low_since = None
                self.collected("host_memory", False)
                return
            self.collected("host_memory", True)
            if value["available_bytes"] >= self.policy["stop"]["min_available_memory_bytes"]:
                self.low_since = None
                return
            if self.low_since is None:
                self.low_since = monotonic
            if monotonic-self.low_since >= self.policy["stop"]["low_memory_seconds"]:
                self.trip("host_memory", "호스트 여유 메모리 1GiB 미만이 15초 지속됐습니다.",
                          "INCONCLUSIVE", value)

    def http(self, point):
        at = utc_time(point["at"])
        if at is None:
            raise ValueError("HTTP 표본 시각 오류")
        timestamp = at.timestamp()
        with self.lock:
            self.http_count += 1
            if point["status"] == 403:
                self.trip("unexpected_403", "정상 요청에서 예상 밖 403을 관측했습니다.", "FAIL", point)
            self.latest_http = max(timestamp, self.latest_http or timestamp)
            start = self.latest_http-self.policy["stop"]["http_window_seconds"]
            self.window.append((timestamp, point["status"] != 200))
            self.window = [p for p in self.window if p[0] > start]
            errors = sum(error for _, error in self.window)
            if (len(self.window) >= self.policy["stop"]["http_min_samples"]
                    and errors/len(self.window) >= self.policy["stop"]["http_error_rate"]):
                self.trip("http_error_rate", "최근 10초의 HTTP 오류·타임아웃 비율이 10% 이상입니다.",
                          "FAIL", dict(samples=len(self.window), errors=errors,
                                       window_seconds=self.policy["stop"]["http_window_seconds"]))

    def containers(self, current, baseline):
        for service in self.policy["required_services"]:
            row, old = current.get(service), baseline[service]
            if (row is None or not row["running"] or row["oom_killed"]
                    or row["id"] != old["id"] or row["restart_count"] != old["restart_count"]
                    or row["started_at"] != old["started_at"]):
                self.trip("container_state", f"필수 서비스 {service}의 종료·OOM·재시작·교체를 관측했습니다.",
                          "FAIL", dict(service=service, before=old, current=row))
                return


class PointReader:
    def __init__(self, path):
        self.path, self.position, self.buffer = path, 0, b""
        self.failed = False

    def read(self):
        if self.failed:
            raise ValueError("HTTP 원본의 이전 형식 오류가 해결되지 않았습니다.")
        with self.path.open("rb") as stream:
            if self.path.stat().st_size < self.position:
                self.failed = True
                raise ValueError("HTTP 원본 파일이 잘렸습니다.")
            stream.seek(self.position)
            data = stream.read()
        self.position += len(data)
        self.buffer += data
        lines = self.buffer.split(b"\n")
        self.buffer = lines.pop()
        if len(self.buffer) > 1024*1024:
            self.failed = True
            raise ValueError("HTTP JSON 행 길이 초과")
        for line in lines:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError("HTTP JSON 형식 오류")
                if item.get("type") != "Point" or item.get("metric") != "http_req_duration":
                    continue
                sample = item.get("data", {})
                tags = sample.get("tags") or {}
                status = tags.get("status")
                duration = sample.get("value")
                if (not isinstance(status, str) or not status.isdigit() or not 0 <= int(status) <= 599
                        or type(duration) not in (int, float) or not math.isfinite(duration) or duration < 0
                        or utc_time(sample.get("time")) is None):
                    raise ValueError("HTTP 표본 필드 오류")
                yield dict(at=sample["time"], status=int(status), duration_ms=duration)
            except Exception:
                self.failed = True
                raise


class AutoStopGuard:
    def __init__(self, policy, output, compose, ids, command, event, memory_provider=None):
        self.policy, self.output, self.compose, self.ids = policy, output, compose, ids
        self.command, self.event, self.memory_provider = command, event, memory_provider or host_memory
        self.rules = StopRules(policy)
        self.reader = PointReader(output / "raw" / "k6-points.jsonl")
        self.stop = threading.Event()
        self.worker = None
        self.resource_worker = None
        self.baseline = {}
        self.resource_samples = 0

    @property
    def abort(self):
        return self.rules.abort

    def collected(self, name, success):
        self.rules.collected(name, success)
        if not success:
            try:
                self.event("error", "자동 중단 감시의 수집 실패: " + name)
            except OSError:
                self.rules.collected("guard_storage", False)

    def states(self, ids):
        template = ('{"id":"{{.Id}}","service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                    '"running":{{.State.Running}},"oom_killed":{{.State.OOMKilled}},'
                    '"restart_count":{{.RestartCount}},"started_at":"{{.State.StartedAt}}"}')
        result = self.command(["docker", "inspect", "--format", template, *ids], timeout=5)
        if result["code"]:
            # 컨테이너 재생성으로 기존 ID가 사라진 경우 현재 ID를 조회해 교체 여부를 확인한다.
            current = self.command(self.compose + ["ps", "-q"], timeout=5)
            if current["code"] or not current["stdout"].split():
                raise RuntimeError("필수 서비스 상태 수집 실패")
            result = self.command(["docker", "inspect", "--format", template,
                                   *current["stdout"].split()], timeout=5)
            if result["code"]:
                raise RuntimeError("필수 서비스 상태 수집 실패")
        states = {}
        for line in result["stdout"].splitlines():
            row = json.loads(line)
            if (not isinstance(row, dict) or not isinstance(row.get("service"), str)
                    or type(row.get("running")) is not bool or type(row.get("oom_killed")) is not bool
                    or type(row.get("restart_count")) is not int or row["restart_count"] < 0
                    or not isinstance(row.get("id"), str) or not row["id"]
                    or utc_time(row.get("started_at")) is None):
                raise ValueError("컨테이너 상태 필드 오류")
            if row["service"] in states:
                raise ValueError("서비스별 단일 컨테이너 구성이 필요합니다.")
            states[row["service"]] = row
        return states

    def preflight(self):
        self.baseline = self.states(self.ids)
        memory = self.memory_provider()
        (self.output / "raw" / "guard-preflight.json").write_text(
            json.dumps(dict(containers=self.baseline, memory=memory), ensure_ascii=False, indent=2), encoding="utf-8")
        if any(s not in self.baseline or not self.baseline[s]["running"] or self.baseline[s]["oom_killed"]
               for s in self.policy["required_services"]):
            raise RuntimeError("필수 서비스가 실행 가능한 상태가 아닙니다.")
        if not valid_memory(memory) or memory["available_bytes"] < self.policy["stop"]["min_available_memory_bytes"]:
            raise RuntimeError("호스트 여유 메모리 1GiB 이상과 수집 기능을 확인해야 합니다.")

    def resources(self):
        at = datetime.now(timezone.utc).isoformat()
        started = time.monotonic()
        data = dict(at=at)
        try:
            memory = self.memory_provider()
            if not valid_memory(memory):
                raise ValueError("호스트 메모리 형식 오류")
            self.rules.memory(memory, time.monotonic())
            data["memory"] = memory
        except Exception:
            self.rules.low_since = None
            self.collected("host_memory", False)
        try:
            states = self.states(self.ids)
            self.rules.containers(states, self.baseline)
            self.collected("container_state", True)
            data["containers"] = states
        except Exception:
            self.collected("container_state", False)
        data["ended_at"] = datetime.now(timezone.utc).isoformat()
        data["command_seconds"] = time.monotonic()-started
        with (self.output / "raw" / "guard-resources.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(data, ensure_ascii=False) + "\n")
        self.resource_samples += 1

    def http(self, grace=False):
        try:
            for point in self.reader.read():
                self.rules.http(point)
            self.collected("http_points", True)
        except FileNotFoundError:
            if not grace:
                self.collected("http_points", False)
        except Exception:
            self.collected("http_points", False)

    def start(self):
        started = time.monotonic()
        def sample():
            while not self.stop.is_set() and self.abort is None:
                self.http(grace=time.monotonic()-started < self.policy["stop"]["http_startup_grace_seconds"])
                if self.stop.wait(self.policy["stop"]["http_poll_seconds"]):
                    break
        def resource_sample():
            while not self.stop.is_set() and self.abort is None:
                try:
                    self.resources()
                except Exception:
                    self.collected("guard_storage", False)
                if self.stop.wait(self.policy["stop"]["resource_interval_seconds"]):
                    break
        self.worker = threading.Thread(target=sample, daemon=True)
        self.resource_worker = threading.Thread(target=resource_sample, daemon=True)
        self.worker.start()
        self.resource_worker.start()

    def close(self):
        self.stop.set()
        for worker in (self.worker, self.resource_worker):
            if worker is None:
                continue
            worker.join(timeout=20)
            if worker.is_alive():
                raise RuntimeError("자동 중단 감시 스레드 종료 미확인")
        # k6 종료 직전 flush된 마지막 HTTP 표본도 확인한다.
        if self.worker is not None:
            self.http()

    def summary(self):
        return dict(abort=self.abort, http_samples=self.rules.http_count,
                    http_stream_complete=not self.reader.buffer and not self.reader.failed,
                    resource_samples=self.resource_samples,
                    collector_failures=dict(self.rules.failures))


class AutomaticStop(Exception):
    pass


def wait_for_load(process, guard, timeout):
    deadline = time.monotonic()+timeout
    while True:
        if guard.abort:
            raise AutomaticStop(guard.abort["reason"])
        code = process.poll()
        if code is not None:
            return code
        if time.monotonic() >= deadline:
            import subprocess
            raise subprocess.TimeoutExpired("k6", timeout)
        time.sleep(.1)


def stop_load(process):
    """k6 프로세스에만 종료를 요청한다. 서비스 컨테이너에는 신호를 보내지 않는다."""
    import os
    import signal
    import subprocess
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
        process.wait(timeout=5)
        return
    except (OSError, ValueError, AttributeError, subprocess.TimeoutExpired):
        pass
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
