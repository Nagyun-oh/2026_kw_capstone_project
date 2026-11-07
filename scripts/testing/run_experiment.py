"""로컬 정상 요청 예비 실험 실행기. Python 표준 라이브러리만 사용한다."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import os
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

from metrics import EVALUATION_VERSION, normalize, assess, parse_lag, resource_peaks
from pipeline import OBSERVATION_VERSION, PipelineObserver
from pipeline import zero_lag
from load_policy import PROFILE, load_policy, assess_performance
from guard import AutoStopGuard, AutomaticStop, wait_for_load, stop_load

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
KST = timezone(timedelta(hours=9))


def now():
    return datetime.now(timezone.utc).isoformat()


def format_record_time(value, default="미확인"):
    """사람이 읽는 보고서 시각. 원본 JSON의 ISO 시각은 바꾸지 않는다."""
    if not value:
        return default
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return "시각 형식 확인 필요"
    if parsed.tzinfo is None:
        return "시간대 확인 필요"
    return parsed.astimezone(KST).strftime("%Y/%m/%d %H:%M:%S") + " +09:00"


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")


def command(args, timeout=15, input_text=None):
    result = subprocess.run(args, capture_output=True, encoding="utf-8",
                            errors="replace", cwd=ROOT, timeout=timeout,
                            shell=False, input=input_text)
    return {"code": result.returncode, "stdout": result.stdout,
            "stderr": result.stderr}


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url")
    p.add_argument("--profile", choices=("local-load-v1",))
    p.add_argument("--rate", type=int, default=1)
    p.add_argument("--seconds", type=int)
    p.add_argument("--round", type=int, default=1)
    p.add_argument("--interval", type=int, default=5)
    p.add_argument("--observe-pipeline", action="store_true",
                   help="읽기 전용 DB·AI 완료 로그·연속 Kafka lag를 추가 관측")
    p.add_argument("--lag-interval", type=int, default=10)
    p.add_argument("--drain-seconds", type=int)
    p.add_argument("--db-time-offset", choices=("+00:00", "+09:00"),
                   help="DB에 실제 저장된 DATETIME의 해석 기준. 관측 근거를 확인한 후 지정")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--check-tools", action="store_true")
    mode.add_argument("--execute", action="store_true")
    a = p.parse_args(argv)
    a.url = a.url or ("http://localhost/" if a.profile else "http://127.0.0.1/")
    a.seconds = a.seconds if a.seconds is not None else (120 if a.profile else 60)
    a.drain_seconds = a.drain_seconds if a.drain_seconds is not None else (60 if a.profile else 30)
    if a.profile:
        if (a.rate not in (1, 3, 5) or a.seconds != 120 or a.drain_seconds != 60
                or a.interval != 5 or a.lag_interval != 10
                or a.url not in ("http://localhost/", "http://localhost:80/")):
            p.error("local-load-v1은 localhost HTTP 80, rate=1/3/5, seconds=120, drain=60, interval=5, lag-interval=10으로 고정됩니다.")
        a.observe_pipeline = True
    u = urlsplit(a.url)
    if not (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost")
            and u.netloc in ("127.0.0.1", "localhost",
                             "127.0.0.1:80", "localhost:80")
            and u.path == "/" and not u.query and not u.fragment):
        p.error("--url은 로컬 WAF의 http://127.0.0.1/ 또는 localhost:80/만 허용합니다.")
    if not (1 <= a.rate <= 5 and 1 <= a.seconds <= 120
            and 1 <= a.round <= 99 and 1 <= a.interval <= 30):
        p.error("범위: rate=1~5, seconds=1~120, round=1~99, interval=1~30")
    if not (5 <= a.lag_interval <= 30 and 1 <= a.drain_seconds <= 120):
        p.error("범위: lag-interval=5~30, drain-seconds=1~120")
    if a.observe_pipeline and a.db_time_offset is None:
        p.error("--observe-pipeline에는 근거를 확인한 --db-time-offset(+00:00 또는 +09:00)이 필요합니다.")
    return a


def reserve(root, run_id, environment="local"):
    from e2e_environment import result_paths
    output, report = result_paths(root, run_id, environment)
    if output.exists() or report.exists():
        raise FileExistsError("같은 실험 ID가 이미 있습니다.")
    output.mkdir(parents=True, exist_ok=False)
    (output / "raw").mkdir()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.touch(exist_ok=False)
    return output, report


def tool_versions():
    versions = {"python": sys.version.split()[0]}
    for name in ("k6", "docker", "git"):
        if not shutil.which(name):
            raise RuntimeError(name + " 명령을 찾지 못했습니다.")
    checks = {
        "k6": ["k6", "version"],
        "docker_client": ["docker", "--version"],
        "docker_server": ["docker", "version", "--format", "{{.Server.Version}}"],
        "compose": ["docker", "compose", "version"],
        "k6_script": ["k6", "inspect", str(HERE / "normal-smoke.js")],
    }
    for name, args in checks.items():
        result = command(args)
        if result["code"]:
            raise RuntimeError(name + " 실행 확인 실패: " + result["stderr"][:300])
        versions[name] = result["stdout"].strip()
    return versions


def report_text(manifest, measured, events, output):
    rows = "\n".join("| " + key + " | " +
                     ("미측정" if value is None else str(value)) + " |"
                     for key, value in measured["http"].items())
    issues = [{**e, "at": format_record_time(e.get("at"))}
              for e in events if e["kind"] == "error"]
    recorded_at = format_record_time(
        manifest.get("started_at") or manifest.get("planned_at"))
    recorded_date = recorded_at.split(" ")[0]
    reasons = "\n".join("- " + reason for reason in measured.get("verdict_reasons", []))
    delta = measured.get("request_count_delta")
    performance_text = ""
    formal = bool(manifest.get("profile"))
    title = "로컬 성능 기준 측정" if formal else "로컬 정상 요청 예비 실험"
    if formal:
        performance_text = f"""
### 확정 성능 기준·자동 중단 — {manifest['profile']}
- 기준 파일 해시: {manifest.get('load_policy_sha256')}
- 실행 전 확정한 기준: raw/load-policy.json 및 manifest.json의 load_policy
- HTTP 목표: p95 ≤ 200ms, p99 ≤ 500ms.
- DB 행 생성→AI 완료 로그 목표: p95 ≤ 2000ms, p99 ≤ 5000ms. 처리 완료 수와 지연 표본 수를 함께 대조.
- 부하·반복 계획: 1→3→5회/초, 각 120초·3회. 이 보고서는 그중 한 회차이며 9회 전체 실행 완료를 의미하지 않음.
- 자동 중단: 예상 밖 403, 최근 10초에 완료 응답 10건 이상·오류율 10% 이상, 필수 서비스 종료·OOM·재시작, 호스트 여유 메모리 1GiB 미만 15초 지속, 같은 필수 수집 연속 2회 실패.
- HTTP 표본 감시: 0.25초 주기 + k6 JSON 출력 지연. 메모리·컨테이너 감시: 5초 + 조회 소요 시간. 순간 장애를 모두 포착하는 실시간 보장은 아님.
- 중단 대상은 k6 프로세스뿐이며 서비스·DB·차단 정책을 자동 변경하지 않음.
- 별도 성능 판정: {json.dumps(measured.get('performance', {'verdict': 'NOT_EVALUATED'}), ensure_ascii=False)}
- 자동 감시 결과: {json.dumps(measured.get('guard', {}), ensure_ascii=False)}
- 원본: raw/k6-points.jsonl, raw/guard-*.json*, raw/load-policy.json. 강제 종료로 summary가 없으면 원본·중단 근거를 보존하고 정상 완료로 처리하지 않음.
"""
    pipeline_text = ""
    if manifest.get("observe_pipeline"):
        observed = measured.get("pipeline", {})
        counts = observed.get("counts", {})
        pipeline_text = f"""
### 추가 서버 계측 — {OBSERVATION_VERSION}
- 별도 관측 판정: {observed.get('verdict', 'INCONCLUSIVE')}
- DB 저장 시각 해석 기준: {manifest.get('db_time_offset')}. 원본 DATETIME과 변환한 UTC를 함께 보존하며 기존 DB 값을 수정하지 않음.
- 목표: HTTP 요청 수와 DB 로그 수·고유 요청 ID를 대조하고, 각 로그의 AI 처리 완료 및 부하 후 연속 두 번의 필수 lag 0을 확인한다.
- 부하 전 DB 읽기 전용 조회·4개 Kafka 경로 확인 실패 시 부하를 시작하지 않는다.
- DB 최종 집계: {json.dumps(counts, ensure_ascii=False)}
- 비동기 지연(ms): {json.dumps(observed.get('latency_ms', {}), ensure_ascii=False)}
- 지연 미확인 건수: {json.dumps(observed.get('invalid_or_unobserved_latency', {}), ensure_ascii=False)}
- Kafka 관측 최대 lag: {json.dumps(observed.get('lag_maxima', []), ensure_ascii=False)}
- lag 주기: {manifest.get('lag_interval')}초 + 실제 명령 소요 시간. 부하 후 추가 관측 상한 {manifest.get('drain_seconds')}초 + 진행 중인 최종 수집 명령 소요 시간.
- lag 0 확인은 표본 관측이며 정확한 적체 해소 시각·구간 최대값 보장이 아님.
- Nginx access 시각은 초 단위이며 요청 시작 시각이 아님. DB created_at은 행 생성 시각이며 커밋 시각이 아님. AI 완료는 서비스 반환 후 로그 시각이다. 시계 동기화는 별도 확인 필요.
- AI 완료 로그가 있고 탐지 행이 없으면 ai_handled_without_detection으로 구분한다. 탐지 행이 없다는 이유만으로 미처리·실패로 세지 않는다.
- 처리 실패·정책상 제외·DLT의 요청별 집계와 알림·실제 차단은 미측정. 이 옵션은 해당 장애 정합성 검증의 완료를 의미하지 않음.
- 별도 관측 근거: {json.dumps(observed.get('reasons', ['수집 미완료']), ensure_ascii=False)}
- 원본: raw/pipeline-*.json, raw/kafka-*.json. IP·본문·원문 애플리케이션 로그는 저장하지 않음.
"""
    return f"""# 실험 기록: {recorded_date} — {title}

## 실행 정보
- 실험 ID: {manifest['id']}
- 실험일자: {recorded_date}
- 시각 표시: 한국 시간(KST), YYYY/MM/DD HH:MM:SS +09:00
- 실행 상태: {manifest['state']}
- 판정: {measured['verdict']}
- 판정 기준 버전: {manifest.get('evaluation_version', '미기록')}
- 시작 / 종료: {format_record_time(manifest.get('started_at'), '미실행')} / {format_record_time(manifest.get('ended_at'), '미종료')}
- 실제 k6 프로세스 구간(초, 시작·종료 처리 포함): {manifest.get('load_elapsed_seconds', '미측정')}
- 실행기 SHA: {manifest.get('runner_sha', '미확인')}
- 작업 트리 변경 파일: {manifest.get('changed_files', '미확인')}
- 대상 앱 SHA / 모델 / DB 데이터량: 미확인. 실행기 SHA로 대체하지 않음.
- 원본: {output.as_posix()}
- 원본은 Git 제외 대상. 보존 위치·기한은 별도 확정 필요.

## S — Situation
로컬 WAF 정상 요청의 HTTP 결과와 자원·Kafka 스냅샷 수집을 확인한다.
가설: 저부하에서 요청을 완료하고 원본·요약·사건 기록을 남길 수 있다.

## T — Task
{'확정한 로컬 성능 기준과 자동 중단 조건으로 한 회차를 측정한다.' if formal else '정상 요청 예비 실험 하나의 실행·수집·기록 기능을 검증한다.'}

## T — Target
- 대상: {manifest['url']}
- 설정 도착률·기간: {manifest['rate']}회/초 × {manifest['seconds']}초
- 계획 참고 건수: {manifest['target_count']}회. 실제 건수와의 차이만으로 실패시키지 않음.
- 실제 요청·완료 반복이 각각 1건 이상이고 두 건수가 같음(반복당 요청 1건).
- 모든 HTTP 응답 200, dropped_iterations 0, 평균·p95·p99·최대 응답 시간 확보, k6 정상 종료·실행 완료.
- p50(중앙값)은 참고 지표로 함께 기록하며, 미측정이면 0으로 채우지 않음. 기존 합격 상한·필수 지표 판정은 유지.
- Docker 표본 1개 이상, Kafka 전후 조회 성공, 실측 파일 확보.
- {'성능 상한과 자동 중단 조건은 아래 확정 성능 기준 절을 따름.' if formal else 'p95·p99의 성능 합격 상한은 아직 정하지 않음. 이번 판정은 지표 확보를 확인함.'}
- 요청 제한 시간 10초, k6 프로세스 대기 상한은 요청 구간 + 40초.
- 도구 확인·전후 수집 시간은 별도이며 각 외부 명령에도 시간 제한 적용.
- {'확정된 요청·로그·AI 처리 경로의 성능 판정이며 탐지 정확도·브라우저 알림·실제 차단 판정은 별도임.' if formal else '이 판정은 예비 실행·수집 기준이며 정확한 요청률 달성·전체 파이프라인·탐지 정확도·차단 성공 판정이 아님.'}

## A — Action
- 도구 버전과 실행 조건: manifest.json
- 실행 명령: {json.dumps(manifest.get('command', []), ensure_ascii=False)}
- 사건별 실제 시각: events.jsonl
- Docker 수집 간격: {manifest['interval']}초 + 각 명령 소요 시간
- Kafka: {'전후·부하 중·종료 후 표본 수집(추가 계측 절 참고).' if manifest.get('observe_pipeline') else '부하 전·후 스냅샷. 연속 수집이나 적체 해소 시간 측정이 아님.'}
- 서비스 중단·설정 변경 없음.

## R — Result
| 지표 | 실측값 |
| --- | --- |
{rows}

- 단위: http_avg_ms·http_p50_ms·http_p95_ms·http_p99_ms·http_max_ms는 ms, normal_ok_rate는 0~1, 나머지는 건수.
- p50·p95·p99는 위 실제 요청 수와 측정 기간을 함께 해석함. HTTP 응답 시간과 AI 처리 완료 지연은 별도임.
- 계획 대비 실제 HTTP 건수 차이(실제 - 계획): {delta if delta is not None else '미측정'}
- 판정 근거:
{reasons or '- 판정 근거 미기록'}
- Docker 표본: {measured['docker_samples']}개
- 컨테이너별 관측 최대값(%; CPU는 100% 초과 가능): {json.dumps(measured['resource_peaks'], ensure_ascii=False)}
- Kafka 조회 성공: {measured['kafka_successful_snapshots']}/{len(measured.get('kafka_snapshots', []))}회
- Kafka group·partition lag 전후 값: metrics.json의 kafka_snapshots
- 수집 파일 해시: metrics.json의 evidence_sha256
- 미측정 항목: {json.dumps(measured.get('unmeasured', ['DB 저장', '탐지 지연', '브라우저 수신', '실제 차단']), ensure_ascii=False)}
- 복구: 서비스 중단 없음. 시작 전 서비스와 최종 상태 대조는 수동 확인.
- 개선 전후 비교: 미실시.
{pipeline_text}
{performance_text}

## T — Trouble
판정 기준 위반·증거 부족 사유는 Result의 판정 근거에 기록한다.
{json.dumps(issues, ensure_ascii=False, indent=2) if issues else '수집된 사건에서 오류 없음. 원인 분석·최종 서비스 상태는 추가 확인 필요.'}

## 후속 확인
실제 로그와 실험 ID를 대조하고 미측정 항목을 별도 검증한다.
관측 근거 없이 성능·안정성 보장이나 원인 확정으로 확대하지 않는다.
"""


def main(argv=None):
    a = arguments(argv)
    policy, policy_hash = load_policy() if a.profile else (None, None)
    policy_bytes = PROFILE.read_bytes() if policy else None
    if policy_bytes is not None and hashlib.sha256(policy_bytes).hexdigest() != policy_hash:
        raise RuntimeError("실행 준비 중 성능 기준 파일이 변경됐습니다.")
    scenario = f"local-load-rps{a.rate}" if a.profile else "local-normal-smoke"
    run_id = (datetime.now(KST).strftime("%Y%m%dT%H%M%S%z")
              + f"-{scenario}-r{a.round:02d}")
    planned = {"id": run_id, "url": a.url, "rate": a.rate,
               "seconds": a.seconds, "interval": a.interval,
               "target_count": a.rate * a.seconds,
               "evaluation_version": EVALUATION_VERSION}
    if policy:
        planned.update(profile=policy["version"], load_policy=policy, load_policy_sha256=policy_hash)
        planned.update(evaluation_version=policy["version"], http_evaluation_version=EVALUATION_VERSION)
    if a.observe_pipeline:
        planned.update(observe_pipeline=True, observation_version=OBSERVATION_VERSION,
                       lag_interval=a.lag_interval, drain_seconds=a.drain_seconds,
                       db_time_offset=a.db_time_offset)
    if a.dry_run:
        print(json.dumps({**planned, "note": "계획만 출력. 외부 명령·HTTP·파일 생성 없음."},
                         ensure_ascii=False, indent=2))
        return 0
    if a.check_tools:
        try:
            print(json.dumps(tool_versions(), ensure_ascii=False, indent=2))
            return 0
        except Exception as error:
            print(str(error), file=sys.stderr)
            return 2

    output, report = reserve(ROOT, run_id)
    manifest = {**planned, "state": "PLANNED", "planned_at": now()}
    if policy:
        manifest["k6_stop_requested"] = False
    manifest["runner_files_sha256"] = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(HERE.iterdir()) if p.suffix in (".py", ".js") and p.is_file()}
    events, samples, kafka = [], [], []
    stop = threading.Event()
    worker = None
    process = None
    load_clock = None
    exit_code = None
    observer = None
    guard = None
    measured = {"http": {}, "verdict": "NOT_EVALUATED", "docker_samples": 0,
                "resource_peaks": {}, "kafka_successful_snapshots": 0}
    lock = threading.Lock()

    def event(kind, message):
        item = {"at": now(), "kind": kind, "message": message}
        with lock:
            events.append(item)
            with (output / "events.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")

    compose = ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml"]

    def lag(label):
        started_at = now()
        started = time.monotonic()
        result = command(compose + ["exec", "-T", "kafka",
                         "kafka-consumer-groups", "--bootstrap-server",
                         "kafka:29092", "--all-groups", "--describe"])
        item = {"at": now(), "label": label,
                "started_at": started_at, "command_seconds": time.monotonic() - started,
                "rows": parse_lag(result["stdout"]), **result}
        kafka.append(item)
        save(output / "raw" / ("kafka-" + label + ".json"), item)
        if result["code"]:
            event("error", "Kafka 조회 실패: " + label)
        return item

    # 실제 외부 명령·HTTP 전에 계획과 S·T·Target을 남긴다.
    if policy:
        (output / "raw" / "load-policy.json").write_bytes(policy_bytes)
    save(output / "manifest.json", manifest)
    report.write_text(report_text(manifest, measured, events, output), encoding="utf-8")
    try:
        manifest["versions"] = tool_versions()
        manifest["runner_sha"] = command(["git", "rev-parse", "HEAD"])["stdout"].strip()
        manifest["changed_files"] = command(["git", "status", "--short",
                                            "--untracked-files=normal"])["stdout"].splitlines()
        if not (ROOT / ".env").is_file():
            raise RuntimeError("프로젝트 루트의 .env가 필요합니다.")
        ids_result = command(compose + ["ps", "-q"])
        if ids_result["code"]:
            raise RuntimeError("Compose 컨테이너 조회 실패")
        ids = ids_result["stdout"].split()
        if not ids:
            raise RuntimeError("실행 중인 프로젝트 컨테이너가 없습니다.")
        images = command(["docker", "inspect", "--format",
                          "{{.Id}} {{.Config.Image}} {{.Image}}", *ids])
        if images["code"]:
            raise RuntimeError("이미지 조회 실패")
        manifest["actual_images"] = images["stdout"].splitlines()
        if policy:
            guard = AutoStopGuard(policy, output, compose, ids, command, event)
            guard.preflight()
        lag("before")
        if kafka[-1]["code"] != 0:
            raise RuntimeError("Kafka 사전 조회 실패. 부하를 시작하지 않습니다.")
        if a.observe_pipeline:
            observer = PipelineObserver(output, compose, run_id, command, lag, event,
                                        interval=a.lag_interval, drain_seconds=a.drain_seconds,
                                        db_time_offset=a.db_time_offset,
                                        on_collection=guard.collected if guard else None,
                                        cancelled=(lambda: guard.abort is not None) if guard else None)
            existing = observer.preflight(kafka[-1])
            if policy and (existing or not zero_lag(kafka[-1], observer.keys)):
                raise RuntimeError("기준 측정 전 실험 ID 중복·이전 적체를 확인해야 합니다.")

        def sample():
            while not stop.is_set():
                try:
                    result = command(["docker", "stats", "--no-stream",
                                      "--format", "json", *ids], timeout=10)
                    if result["code"]:
                        raise RuntimeError("Docker stats 종료 코드 오류")
                    rows = [json.loads(line) for line in result["stdout"].splitlines()
                            if line.strip()]
                    if not rows:
                        raise ValueError("Docker 표본 없음")
                    samples.append({"at": now(), "containers": rows})
                    if guard:
                        guard.collected("docker_stats", True)
                except Exception as error:
                    event("error", "자원 수집 실패: " + str(error))
                    if guard:
                        guard.collected("docker_stats", False)
                if stop.wait(a.interval):
                    break

        env = dict(os.environ, K6_NO_USAGE_REPORT="true",
                   TARGET_URL=a.url, RUN_RATE=str(a.rate),
                   RUN_SECONDS=str(a.seconds), RUN_ID=run_id,
                   SUMMARY_PATH=str(output / "raw" / "k6-summary.json"))
        args = ["k6", "run", "--no-color", str(HERE / "normal-smoke.js")]
        if policy:
            env["LOAD_POLICY_JSON"] = json.dumps(policy)
            args[3:3] = ["--out", "json=" + str(output / "raw" / "k6-points.jsonl")]
        manifest.update(state="RUNNING", started_at=now(), command=args)
        save(output / "manifest.json", manifest)
        event("start", "로컬 성능 기준 측정 시작" if policy else "정상 요청 예비 실험 시작")
        worker = threading.Thread(target=sample, daemon=True)
        worker.start()
        with (output / "raw" / "k6-console.log").open("w", encoding="utf-8") as log:
            popen_options = dict(cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, shell=False)
            if policy and os.name == "nt":
                popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            load_clock = time.monotonic()
            process = subprocess.Popen(args, **popen_options)
            if guard:
                guard.start()
            if observer:
                observer.start()
            exit_code = wait_for_load(process, guard, a.seconds+40) if guard else process.wait(timeout=a.seconds+40)
            manifest["load_ended_at"] = now()
            manifest["load_elapsed_seconds"] = time.monotonic()-load_clock
        manifest["state"] = "COMPLETED"
    except AutomaticStop as error:
        manifest["state"] = "ABORTED"
        event("abort", str(error))
    except (KeyboardInterrupt, subprocess.TimeoutExpired) as error:
        manifest["state"] = "ABORTED"
        event("error", "중단: " + type(error).__name__)
    except Exception as error:
        manifest["state"] = "BLOCKED" if process is None else "ABORTED"
        event("error", str(error))
    finally:
        if process is not None and process.poll() is None:
            try:
                if policy:
                    manifest["k6_stop_requested"] = True
                stop_load(process)
            except (OSError, subprocess.TimeoutExpired) as error:
                event("error", "k6 종료 확인 실패: " + str(error))
        manifest.setdefault("load_ended_at", now() if process is not None else None)
        if load_clock is not None:
            manifest.setdefault("load_elapsed_seconds", time.monotonic()-load_clock)
        if process is not None and exit_code is None:
            exit_code = process.poll()
        if policy:
            manifest["k6_exit_confirmed"] = process is None or process.poll() is not None
        if observer:
            try:
                observer.close()
            except Exception as error:
                event("error", "연속 Kafka 수집 종료 실패: " + type(error).__name__)
        stop.set()
        if worker:
            worker.join(timeout=15)
            if worker.is_alive():
                event("error", "자원 수집 스레드 종료 미확인")
        if process is not None:
            try:
                lag("after")
            except Exception as error:
                event("error", "종료 후 Kafka 수집 실패: " + str(error))
        summary_path = output / "raw" / "k6-summary.json"
        try:
            measured["http"] = normalize(json.loads(summary_path.read_text(encoding="utf-8")))
        except Exception as error:
            event("error", "k6 결과 미확보: " + str(error))
            measured["http"] = dict.fromkeys(
                ["http_requests", "completed_iterations", "http_avg_ms", "http_p50_ms", "http_p95_ms",
                 "http_p99_ms", "http_max_ms", "normal_ok_rate", "dropped_iterations"])
        if observer and process is not None and manifest["state"] == "COMPLETED":
            try:
                measured["pipeline"] = observer.finish(
                    measured["http"].get("http_requests"), manifest["started_at"],
                    manifest["load_ended_at"])
            except (Exception, KeyboardInterrupt) as error:
                event("error", "추가 서버 계측 미완료: " + type(error).__name__)
                if isinstance(error, KeyboardInterrupt):
                    manifest["state"] = "ABORTED"
                measured["pipeline"] = dict(verdict="INCONCLUSIVE", reasons=["추가 계측을 완료하지 못했습니다."])
        if guard:
            try:
                guard.close()
            except Exception as error:
                event("error", "자동 중단 감시 종료 실패: " + type(error).__name__)
            measured["guard"] = guard.summary()
            save(output / "raw" / "guard-summary.json", measured["guard"])
            if guard.abort:
                manifest["state"] = "ABORTED"
                manifest["abort_reason"] = guard.abort
        event("end", "실행 종료. state=" + manifest["state"])
        manifest.update(ended_at=now(), exit_code=exit_code)
        complete = bool(samples) and len(kafka) >= 2 and all(k["code"] == 0 for k in kafka)
        complete = complete and all(k["rows"] and all(r["lag"] is not None
                                      for r in k["rows"]) for k in kafka)
        complete = complete and not any(e["kind"] == "error" for e in events)
        if policy:
            guard_data = measured.get("guard", {})
            complete = (complete and guard_data.get("http_stream_complete", False)
                        and guard_data.get("http_samples") == measured["http"].get("http_requests")
                        and guard_data.get("resource_samples", 0) > 0)
        decision = assess(measured["http"], exit_code, complete, manifest["state"])
        if a.observe_pipeline:
            observed = measured.get("pipeline", dict(verdict="INCONCLUSIVE", reasons=["추가 서버 계측을 시작하지 못했습니다."]))
            measured["pipeline"] = observed
            if "FAIL" in (decision["verdict"], observed["verdict"]):
                decision["verdict"] = "FAIL"
            elif "INCONCLUSIVE" in (decision["verdict"], observed["verdict"]):
                decision["verdict"] = "INCONCLUSIVE"
            decision["reasons"].extend(observed["reasons"])
        if policy:
            performance = assess_performance(policy, measured["http"], measured.get("pipeline", {}),
                                             guard.abort if guard else None,
                                             load_elapsed=manifest.get("load_elapsed_seconds"))
            measured["performance"] = performance
            priorities = {"PASS": 0, "INCONCLUSIVE": 1, "FAIL": 2}
            decision["verdict"] = max((decision["verdict"], performance["verdict"]), key=priorities.get)
            decision["reasons"].extend(performance["reasons"])
        actual_count = measured["http"]["http_requests"]
        measured.update(
            verdict=decision["verdict"],
            verdict_reasons=decision["reasons"],
            request_count_delta=(actual_count - planned["target_count"]
                                 if actual_count is not None else None),
            docker_samples=len(samples),
            resource_peaks=resource_peaks(samples),
            kafka_snapshots=[{"at": k["at"], "label": k["label"],
                              "rows": k["rows"]} for k in kafka],
            kafka_successful_snapshots=sum(k["code"] == 0 for k in kafka),
            unmeasured=["DB 저장", "탐지 지연", "브라우저 수신", "실제 차단"])
        if a.observe_pipeline:
            measured["unmeasured"] = ["정확한 요청 시작→커밋 지연", "실패·정책상 제외·DLT의 요청별 집계",
                                      "브라우저 수신", "실제 차단"]
        save(output / "raw" / "docker-stats.json", samples)
        measured["evidence_sha256"] = {
            str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (output / "raw").iterdir() if p.is_file()}
        save(output / "manifest.json", manifest)
        save(output / "metrics.json", measured)
        report.write_text(report_text(manifest, measured, events, output),
                          encoding="utf-8")
        print("결과:", measured["verdict"], "\n보고서:", report, "\n원본:", output)
    return 0 if measured["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

'''
- 역할 : 조건 검증·실행·수집을 묶는 공통 실행기
- 구현된 기능: 입력 검증/도구 확인 및 실행/Docker/Kafka 수집/파일 저장/STAR-T 초안 생성
'''
