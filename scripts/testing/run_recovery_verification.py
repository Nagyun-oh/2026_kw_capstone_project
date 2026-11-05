"""전용 MySQL 스키마·embedded Kafka에서 정합성·프로세스 복구를 검증한다.

기존 DB는 구조와 건수만 읽는다. 기존 컨테이너·그룹·offset은 변경하지 않는다.
테스트 스키마는 증거 보존을 위해 자동 삭제하지 않는다. 비밀번호는 메모리/자식 환경에만 전달한다.
"""
import argparse
import ctypes
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml"]
KST = timezone(timedelta(hours=9))
CASES = {
    "atomic_rollback": "원본 로그·outbox 동시 롤백 / 미커밋 작업 선점 불가",
    "committed_publish": "커밋 후 실제 Kafka ACK / SENT 기록",
    "network_recovery": "실제 TCP 접속 실패 후 PENDING 보존·재전송",
    "pending_restart": "발행 전 JVM 강제 종료 후 새 JVM 복구",
    "lease_restart": "선점 직후 종료 / 60초 리스 만료·소유권 검증",
    "ack_gap_duplicates": "ACK 후 종료 / 재발행·중복 결과의 탐지·알림 중복 방지",
    "dlt_offset_recovery": "DLT 전송 실패 시 offset 보존 / 복구 후 커밋",
}


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(args, *, stdin=None, timeout=60):
    p = subprocess.run(args, cwd=ROOT, input=stdin, capture_output=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    if p.returncode:
        # 인증값이나 임의 원문을 예외 메시지로 출력하지 않는다.
        raise RuntimeError("외부 명령 실패: " + args[0] + " (exit=" + str(p.returncode) + ")")
    return p.stdout


def memory():
    class Memory(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
            (name, ctypes.c_ulonglong) for name in
            ("total", "available", "page", "available_page", "virtual", "available_virtual", "extended")]
    m = Memory()
    m.length = ctypes.sizeof(m)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
        raise RuntimeError("Windows 메모리 조회 실패")
    return m.available


def mysql(sql, database="security_db"):
    if database != "security_db" and not re.fullmatch(r"dg_recovery_[a-z0-9_]+", database):
        raise ValueError("격리 스키마 이름 필요")
    return run(COMPOSE + ["exec", "-T", "db", "sh", "-c",
        'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --batch --skip-column-names ' + database], stdin=sql)


def live_snapshot():
    return {
        "containers": [{key: c.get(key) for key in ("Service", "ID", "Image", "State", "Health", "Status")}
                       for c in (json.loads(row) for row in run(COMPOSE + ["ps", "--all", "--format", "json"]).splitlines() if row.strip())],
        "business_counts": mysql("SELECT 'network_logs',COUNT(*) FROM network_logs UNION ALL SELECT 'detected_threats',COUNT(*) FROM detected_threats UNION ALL SELECT 'ip_blacklist',COUNT(*) FROM ip_blacklist;")
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--execute", action="store_true", required=True)
    p.add_argument("--round", type=int, default=1)
    args = p.parse_args()
    started = datetime.now(KST)
    exp = started.strftime("%Y%m%dT%H%M%S%z") + f"-local-recovery-r{args.round:02d}"
    raw = ROOT / "build/test-runs" / exp
    report = ROOT / "docs/testing/local/runs" / (exp + ".md")
    report.parent.mkdir(parents=True, exist_ok=True)
    raw.mkdir(parents=True, exist_ok=False)
    schema = "dg_recovery_" + started.strftime("%Y%m%d_%H%M%S")
    baseline = f"""# 실험 기록: {started:%Y/%m/%d} — AI 요청·결과 정합성 및 복구 검증

## 실행 정보

- 실험 ID: `{exp}`
- 시작: {started:%Y/%m/%d %H:%M:%S} +09:00
- 환경: 로컬 Windows / 전용 MySQL `{schema}` / embedded KRaft Kafka
- 상태: RUNNING / 판정: NOT_EVALUATED
- 앱 SHA·작업 트리·컨테이너: 원본 `environment.json` 참조
- 이전 관측: r15 원본 로그 커밋 경합·결과 예외 삼킴. 기존 r15 판정은 보존.
- 원본: `build/test-runs/{exp}/`

## S — Situation

기준 부하에서 HTTP/DB 121건 중 AI 완료 119건이 확인됐다. 이후 사용자가 outbox와 Consumer 재시도/DLT를 구현했다.
이번에는 실제 JPA/JDBC 저장과 Kafka ACK를 사용해 복구·중복 처리 경계를 검증한다.

## T — Task / Target

사전 기준: 아래 7개 필수 사례의 모든 assertion과 증거가 일치하면 PASS. assertion 실패는 FAIL, 준비·자원 부족·증거 누락은 INCONCLUSIVE.
네트워크 장애는 테스트 producer의 닫힌 loopback 포트에만 주입하고, 종료는 소유한 자식 JVM만 `Runtime.halt`한다.
기존 DB 데이터·Kafka offset·실행 중 컨테이너는 수정하지 않는다. 여유 메모리 1GiB 미만 또는 전체 10분 초과 시 소유한 테스트 프로세스만 종료한다.
표본 1회씩의 기능·복구 검증이며 성능 백분위·최대 처리량 측정은 해당 없음.

| 필수 사례 | 사전 기준 |
| --- | --- |
""" + "".join(f"| {name} | {text} |\n" for name, text in CASES.items()) + """

## A — Action

실행 중. 실제 시각·사건은 `events.jsonl`, 사례별 assertion 증거는 `observations.jsonl`에 저장한다.

## R — Result

실행 중. 실제 브라우저·웹소켓 전달, 기존 Kafka 컨테이너 중단, EC2 장애는 이 검증의 범위 밖이다.

## Trouble

실행 후 실제 관측한 문제와 한계를 작성한다.
"""
    report.write_text(baseline, encoding="utf-8")
    events = raw / "events.jsonl"
    def event(kind, **values):
        with events.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"at": now(), "event": kind, **values}, ensure_ascii=False) + "\n")
    result = {"id": exp, "schema": schema, "started_at": now(), "status": "INCONCLUSIVE"}
    child = None
    try:
        available = memory()
        event("preflight", available_memory_bytes=available)
        if available < 1024**3:
            raise RuntimeError("최소 여유 메모리 1GiB 미달")
        before = live_snapshot()
        java_test = ROOT / "backend/src/test/java/com/example/security_log_system/recovery/RecoveryVerificationTest.java"
        env_info = {"sha": run(["git", "rev-parse", "HEAD"]).strip(),
                    "branch": run(["git", "branch", "--show-current"]).strip(),
                    "dirty": run(["git", "status", "--short"]),
                    "test_sha256": hashlib.sha256(java_test.read_bytes()).hexdigest(),
                    "app_source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                          for path in (ROOT / "backend/src/main").rglob("*") if path.is_file()},
                    "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "before": before, "available_memory_bytes": available}
        save(raw / "environment.json", env_info)
        dump = run(COMPOSE + ["exec", "-T", "db", "sh", "-c",
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -u root --no-data --skip-triggers --no-tablespaces --set-gtid-purged=OFF security_db'])
        if re.search(r"(?im)^\s*(USE |CREATE DATABASE|DROP DATABASE)", dump):
            raise RuntimeError("스키마 덤프의 대상 변경문 거부")
        mysql("CREATE DATABASE `" + schema + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin;")
        mysql(dump, schema)
        event("isolated_schema_ready", name=schema, structure_sha256=hashlib.sha256(dump.encode()).hexdigest())
        # 값은 출력하거나 파일에 저장하지 않는다.
        password = run(COMPOSE + ["exec", "-T", "db", "printenv", "MYSQL_ROOT_PASSWORD"]).rstrip("\r\n")
        child_env = os.environ.copy()
        child_env.update(DG_RECOVERY_DB_URL="jdbc:mysql://127.0.0.1:3306/" + schema + "?serverTimezone=Asia/Seoul",
                         DG_RECOVERY_DB_USER="root", DG_RECOVERY_DB_PASSWORD=password,
                         DG_RECOVERY_OUTPUT=str(raw))
        init = raw / "recovery.init.gradle"
        init.write_text("allprojects { tasks.withType(Test).configureEach { maxHeapSize='768m'; reports.junitXml.outputLocation=file('" + raw.as_posix() + "/junit'); testLogging { events 'passed','failed','skipped' } } }\n", encoding="utf-8")
        command = [str(ROOT / "backend/gradlew.bat"), "test", "--offline", "--no-daemon", "--rerun-tasks", "-I", str(init),
                   "--tests", "*RecoveryVerificationTest", "--tests", "*AiRequestOutboxPublisherTest",
                   "--tests", "*AiResultConsumerTest", "--tests", "*LogConsumerTest",
                   "--tests", "*PipelineKafkaErrorConfigTest", "--tests", "*LogServiceTest", "--tests", "*ThreatServiceTest"]
        save(raw / "command.json", {"args": command, "secrets": "환경 값은 기록하지 않음"})
        event("test_started")
        with (raw / "gradle.log").open("w", encoding="utf-8") as log:
            child = subprocess.Popen(command, cwd=ROOT / "backend", env=child_env, stdout=log, stderr=subprocess.STDOUT)
            child_env.pop("DG_RECOVERY_DB_PASSWORD", None)
            password = None
            began = time.monotonic()
            while child.poll() is None:
                free = memory()
                event("resource_sample", available_memory_bytes=free)
                if free < 1024**3 or time.monotonic() - began > 600:
                    # 이번 실행이 소유한 프로세스 트리만 종료한다.
                    subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"], capture_output=True)
                    raise RuntimeError("테스트 전용 작업 중단: 메모리/시간 기준")
                time.sleep(3)
        result["exit_code"] = child.returncode
        junit = []
        for path in (raw / "junit").glob("TEST-*.xml"):
            suite = ET.parse(path).getroot()
            junit.append({key: suite.get(key) for key in ("name", "tests", "failures", "errors", "skipped", "time")})
        observations = [json.loads(line) for line in (raw / "observations.jsonl").read_text(encoding="utf-8").splitlines()] if (raw / "observations.jsonl").exists() else []
        result.update(junit=junit, observations=observations)
        recovered = {row["case"] for row in observations}
        failed = sum(int(s.get("failures") or 0) + int(s.get("errors") or 0) for s in junit)
        result["status"] = "FAIL" if failed else "PASS" if child.returncode == 0 and recovered == set(CASES) else "INCONCLUSIVE"
        result["after"] = live_snapshot()
        ids_before = {c["Service"]: c["ID"] for c in before["containers"]}
        ids_after = {c["Service"]: c["ID"] for c in result["after"]["containers"]}
        result["live_container_ids_unchanged"] = ids_before == ids_after
        if ids_before != ids_after:
            result["status"] = "INCONCLUSIVE"
    except (Exception, KeyboardInterrupt) as exc:
        if child is not None and child.poll() is None:
            subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"], capture_output=True)
        result["error"] = type(exc).__name__ + ": " + str(exc)
        event("interrupted", code=type(exc).__name__, message=str(exc))
    result["ended_at"] = now()
    save(raw / "result.json", result)
    event("finished", status=result["status"])
    summary = "\n\n## 최종 결과\n\n"
    summary += f"- 판정: **{result['status']}**\n- 종료: {datetime.now(KST):%Y/%m/%d %H:%M:%S} +09:00\n"
    summary += f"- 격리 DB: `{schema}` (증거 보존, 자동 삭제 안 함)\n"
    if result.get("error"):
        summary += "- 준비·실행 문제: " + result["error"] + "\n"
    for row in result.get("observations", []):
        summary += "- " + row["case"] + ": `" + json.dumps(row["observations"], ensure_ascii=False) + "`\n"
    summary += "\n실제 웹소켓·브라우저 팝업, Kafka 컨테이너 자체 재시작, EC2 및 부하 재측정은 미실행이다. 메신저 전송 경계는 mock으로 대조한다.\n"
    final_text = baseline.replace("상태: RUNNING / 판정: NOT_EVALUATED", "상태: FINISHED / 판정: " + result["status"])
    final_text = final_text.replace("실행 중. 실제 시각·사건은", "실제 시각·사건은")
    final_text = final_text.replace("실행 중. 실제 브라우저", "실제 브라우저")
    report.write_text(final_text + summary, encoding="utf-8")
    print("결과:", result["status"])
    print("보고서:", report)
    print("원본:", raw)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
