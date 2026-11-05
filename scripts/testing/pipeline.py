"""로컬 실험의 읽기 전용 DB·AI 완료 로그·연속 lag 관측. 모델 판정은 변경하지 않는다."""
from datetime import datetime, timezone
import json
import math
import re
import threading
import time
from urllib.parse import quote

OBSERVATION_VERSION = "local-pipeline-v2"
EXPECTED_STREAMS = {
    ("log-group", "log-topic"),
    ("ai-service-group", "ai-request-topic"),
    ("ai-result-group", "ai-result-topic"),
    ("waf-detection-group", "waf-detection-topic"),
}
ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
RECEIPT = re.compile(r"AI analysis result received\. logId=(\d+)\b")


def utc_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except ValueError:
        return None


def request_path(run_id):
    return "/?test_run=" + quote(run_id, safe="~()*!.'-")


def database_sql(run_id, db_time_offset="+00:00"):
    if db_time_offset not in ("+00:00", "+09:00"):
        raise ValueError("DB 시각 해석 기준 확인 필요")
    # 값을 SQL 문법으로 삽입하지 않는다. 실험 URL은 UTF-8 16진수 리터럴로 전달한다.
    encoded_path = request_path(run_id).encode("utf-8").hex()
    return f"""START TRANSACTION READ ONLY;
SELECT JSON_OBJECT(
  'log_id', n.id, 'request_id', n.request_id, 'status_code', n.status_code,
  'log_row_raw', DATE_FORMAT(n.created_at, '%Y-%m-%dT%H:%i:%s.%f'),
  'log_row_at', DATE_FORMAT(CONVERT_TZ(n.created_at, '{db_time_offset}', '+00:00'),
                           '%Y-%m-%dT%H:%i:%s.%fZ'),
  'waf_access_at', CASE WHEN JSON_VALID(n.raw_log)
    THEN JSON_UNQUOTE(JSON_EXTRACT(n.raw_log, '$.time')) ELSE NULL END,
  'ai_detection_count', (SELECT COUNT(*) FROM detected_threats t
    WHERE t.log_id=n.id AND t.threat_type='AI Detection'),
  'waf_detection_count', (SELECT COUNT(*) FROM detected_threats t
    WHERE t.log_id=n.id AND t.threat_type='WAF Detection')
)
FROM network_logs n
WHERE BINARY n.request_url = BINARY CONVERT(0x{encoded_path} USING utf8mb4)
ORDER BY n.id;
ROLLBACK;
"""


def parse_database(text):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError("DB 결과 형식 오류")
        for key in ("log_id", "status_code", "ai_detection_count", "waf_detection_count"):
            value = row.get(key)
            if type(value) is not int or value < 0 or (key == "log_id" and value == 0):
                raise ValueError("DB 결과 숫자 형식 오류")
        if any(row.get(k) is not None and not isinstance(row[k], str)
               for k in ("request_id", "log_row_raw", "log_row_at", "waf_access_at")):
            raise ValueError("DB 결과 문자열 형식 오류")
        # IP·요청 본문·모델 설명을 수집하지 않는다.
        rows.append({k: row.get(k) for k in (
            "log_id", "request_id", "status_code", "log_row_raw", "log_row_at", "waf_access_at",
            "ai_detection_count", "waf_detection_count")})
    if len({r["log_id"] for r in rows}) != len(rows):
        raise ValueError("DB 결과의 로그 ID 중복")
    return rows


def parse_receipts(text, log_ids):
    found = []
    for line in text.splitlines():
        match = RECEIPT.search(line)
        if not match or int(match[1]) not in log_ids:
            continue
        timestamps = ISO_TIME.findall(line[:match.start()])
        if timestamps and utc_time(timestamps[-1]) is not None:
            found.append({"log_id": int(match[1]), "handled_at": timestamps[-1]})
    return found


def distribution(values):
    values = sorted(values)
    if not values:
        return dict(count=0, avg_ms=None, p50_ms=None, p95_ms=None, p99_ms=None, max_ms=None)

    def percentile(q):
        index = (len(values) - 1) * q
        lo, hi = math.floor(index), math.ceil(index)
        return values[lo] + (values[hi] - values[lo]) * (index - lo)

    return dict(count=len(values), avg_ms=sum(values) / len(values),
                p50_ms=percentile(.5), p95_ms=percentile(.95),
                p99_ms=percentile(.99), max_ms=values[-1])


def account(rows, receipts, expected):
    first = {}
    for receipt in receipts:
        at = utc_time(receipt["handled_at"])
        if at is not None:
            key = receipt["log_id"]
            first[key] = min(at, first.get(key, at))
    ids = {row["log_id"] for row in rows}
    completed = ids & first.keys()
    request_ids = [r["request_id"] for r in rows if r["request_id"]]
    delays = {k: [] for k in (
        "waf_access_to_log_row", "log_row_to_ai_handled", "waf_access_to_ai_handled")}
    invalid = {k: 0 for k in delays}
    for row in rows:
        access, saved = utc_time(row["waf_access_at"]), utc_time(row["log_row_at"])
        handled = first.get(row["log_id"])
        # 다른 구간과 모순되는 DB 시각을 지연 수치로 발표하지 않는다.
        if saved is not None and ((access is not None and saved < access)
                                  or (handled is not None and saved > handled)):
            saved = None
        for key, start, end in (
            ("waf_access_to_log_row", access, saved),
            ("log_row_to_ai_handled", saved, handled),
            ("waf_access_to_ai_handled", access, handled)):
            if start is not None and end is not None and end >= start:
                delays[key].append((end - start).total_seconds() * 1000)
            else:
                invalid[key] += 1
    counts = dict(
        expected_http_requests=expected, saved_logs=len(rows),
        distinct_request_ids=len(set(request_ids)), missing_request_ids=len(rows)-len(request_ids),
        duplicate_request_ids=len(request_ids)-len(set(request_ids)),
        ai_handled_logs=len(completed), ai_unconfirmed_logs=len(ids-completed),
        ai_handled_with_detection=sum(r["log_id"] in completed and r["ai_detection_count"] > 0 for r in rows),
        ai_handled_without_detection=sum(r["log_id"] in completed and r["ai_detection_count"] == 0 for r in rows),
        ai_detection_rows=sum(r["ai_detection_count"] for r in rows),
        waf_detection_rows=sum(r["waf_detection_count"] for r in rows),
        logs_with_duplicate_ai_detections=sum(r["ai_detection_count"] > 1 for r in rows),
        extra_ai_receipt_events=sum(r["log_id"] in ids for r in receipts)-len(completed),
        processing_failures=None, policy_excluded=None, dlt_records=None,
    )
    return dict(counts=counts, latency_ms={k: distribution(v) for k, v in delays.items()},
                invalid_or_unobserved_latency=invalid)


def partition_keys(snapshot):
    return {(r["group"], r["topic"], r["partition"]) for r in snapshot["rows"]
            if (r["group"], r["topic"]) in EXPECTED_STREAMS}


def lag_complete(snapshot, expected_keys):
    keys = partition_keys(snapshot)
    streams = {(g, t) for g, t, _ in keys}
    return (snapshot.get("code") == 0 and streams == EXPECTED_STREAMS
            and keys >= expected_keys and all(
                type(r["lag"]) is int and r["lag"] >= 0 for r in snapshot["rows"]
                if (r["group"], r["topic"]) in EXPECTED_STREAMS))


def zero_lag(snapshot, expected_keys):
    return lag_complete(snapshot, expected_keys) and all(
        r["lag"] == 0 for r in snapshot["rows"]
        if (r["group"], r["topic"]) in EXPECTED_STREAMS)


def lag_maxima(snapshots):
    maxima = {}
    for snapshot in snapshots:
        if snapshot.get("code") != 0:
            continue
        for row in snapshot["rows"]:
            if (row["group"], row["topic"]) not in EXPECTED_STREAMS:
                continue
            key = (row["group"], row["topic"], row["partition"])
            item = maxima.setdefault(key, dict(group=key[0], topic=key[1], partition=key[2],
                                               observed_max_lag=None, known_samples=0, unknown_samples=0))
            value = row["lag"]
            if type(value) is int and value >= 0:
                old = item["observed_max_lag"]
                item["observed_max_lag"] = value if old is None else max(value, old)
                item["known_samples"] += 1
            else:
                item["unknown_samples"] += 1
    return list(maxima.values())


class PipelineObserver:
    def __init__(self, output, compose, run_id, command, lag, event, *, interval=10, drain_seconds=30,
                 db_time_offset="+00:00", on_collection=None, cancelled=None):
        self.output, self.compose, self.run_id = output, compose, run_id
        self.command, self.lag, self.event = command, lag, event
        self.interval, self.drain_seconds = interval, drain_seconds
        self.db_time_offset = db_time_offset
        self.on_collection = on_collection or (lambda name, success: None)
        self.cancelled = cancelled or (lambda: False)
        self.keys, self.snapshots, self.errors = set(), [], []
        self.stop = threading.Event()
        self.worker = None

    def write(self, name, value):
        (self.output / "raw" / name).write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def database(self, label):
        # 비밀번호는 컨테이너 환경에서만 읽는다. 호스트 인자·보고서에 펼치지 않는다.
        args = self.compose + ["exec", "-T", "db", "sh", "-c",
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -u root -D security_db '
            '--default-character-set=utf8mb4 --batch --raw --skip-column-names']
        result = self.command(args, timeout=15, input_text=database_sql(self.run_id, self.db_time_offset))
        if result["code"] != 0:
            raise RuntimeError("읽기 전용 DB 조회 실패")
        rows = parse_database(result["stdout"])
        self.write("pipeline-db-" + label + ".json", rows)
        return rows

    def snapshot(self, label):
        item = self.lag(label)
        self.keys.update(partition_keys(item))
        self.snapshots.append(item)
        if not lag_complete(item, self.keys):
            raise RuntimeError("필수 4개 Kafka group·topic·partition lag 미확인")
        return item

    def preflight(self, before):
        self.keys = partition_keys(before)
        self.snapshots.append(before)
        if not lag_complete(before, self.keys):
            raise RuntimeError("파이프라인 사전 확인: 필수 4개 Kafka 경로가 준비되지 않음")
        return self.database("preflight")

    def start(self):
        def sample():
            count = 0
            while not self.stop.is_set():
                count += 1
                try:
                    self.snapshot(f"during-{count:04d}")
                    self.on_collection("kafka_lag", True)
                except Exception as error:
                    self.errors.append(type(error).__name__)
                    self.event("error", "연속 Kafka lag 수집 실패")
                    self.on_collection("kafka_lag", False)
                if self.stop.wait(self.interval):
                    break
        self.worker = threading.Thread(target=sample, daemon=True)
        self.worker.start()

    def close(self):
        self.stop.set()
        if self.worker:
            self.worker.join(timeout=20)
            if self.worker.is_alive():
                raise RuntimeError("연속 Kafka 수집 종료 미확인")

    def finish(self, expected, since, load_ended_at):
        self.close()
        deadline = time.monotonic() + self.drain_seconds
        rows, receipts, zero_streak, rounds = [], [], 0, 0
        database_observed = False
        ai_log_observed = False
        confirmed_at = None
        while True:
            if self.cancelled():
                break
            rounds += 1
            label = f"drain-{rounds:04d}"
            try:
                snap = self.snapshot(label)
                zero_streak = zero_streak + 1 if zero_lag(snap, self.keys) else 0
                rows = self.database(label)
                database_observed = True
                result = self.command(self.compose + ["logs", "--no-color", "--timestamps",
                    "--since", since, "--tail", "20000", "backend"], timeout=15)
                if result["code"]:
                    raise RuntimeError("AI 처리 완료 로그 조회 실패")
                receipts = parse_receipts(result["stdout"], {r["log_id"] for r in rows})
                ai_log_observed = True
                self.write("pipeline-ai-" + label + ".json", receipts)
                self.on_collection("pipeline_final", True)
                progress = account(rows, receipts, expected)
                counts = progress["counts"]
                if (expected is not None and expected > 0 and len(rows) == expected
                        and counts["ai_handled_logs"] == expected and zero_streak >= 2):
                    confirmed_at = snap["at"]
                    break
            except Exception as error:
                self.errors.append(type(error).__name__)
                zero_streak = 0
                self.event("error", "최종 파이프라인 수집 실패(상세 개인정보는 기록하지 않음)")
                self.on_collection("pipeline_final", False)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # 다음 수집 라운드 전에 중단 요청을 확인한다.
            if self.cancelled():
                break
            time.sleep(min(self.interval, remaining))
        result = account(rows, receipts, expected)
        if not database_observed:
            result["counts"] = {key:(value if key=="expected_http_requests" else None)
                                for key,value in result["counts"].items()}
        counts = result["counts"]
        failures, unknowns = [], []
        cancelled = self.cancelled()
        if cancelled:
            unknowns.append("자동 중단 요청으로 최종 대기 구간의 관측을 중단했습니다.")
        if self.errors:
            unknowns.append("관측 중 수집 오류가 있어 전체 구간의 증거가 불완전합니다.")
        elif not cancelled and database_observed and expected is not None and len(rows) != expected:
            failures.append("최종 대기 구간 내 HTTP 요청 수와 DB 로그 수가 다릅니다. 영구 누락 여부는 추가 확인이 필요합니다.")
        if counts["duplicate_request_ids"] or counts["missing_request_ids"] or counts["logs_with_duplicate_ai_detections"]:
            failures.append("요청 ID 누락·중복 또는 동일 로그의 중복 AI 탐지 행을 관측했습니다.")
        if expected is None or expected <= 0 or counts["ai_handled_logs"] != expected:
            unknowns.append("요청별 AI 결과 처리 완료를 모두 확인하지 못했습니다.")
        if confirmed_at is None:
            unknowns.append("DB·AI 완료 대조 및 연속 두 번의 lag 0 확인이 대기 구간 내 완료되지 않았습니다.")
        if not any(s.get("label", "").startswith("during-") for s in self.snapshots):
            unknowns.append("부하 구간의 Kafka lag 표본을 확보하지 못했습니다.")
        if any(result["invalid_or_unobserved_latency"].values()) or not rows:
            unknowns.append("시각 누락·역전 또는 완료 미확인 때문에 일부 비동기 지연은 미측정입니다.")
        result.update(version=OBSERVATION_VERSION,
            verdict="FAIL" if failures else "INCONCLUSIVE" if unknowns else "PASS",
            reasons=failures + unknowns or ["관측 범위의 HTTP·DB·AI 완료 대조와 연속 lag 수집 기준을 충족했습니다."],
            lag_maxima=lag_maxima(self.snapshots),
            lag_samples=len(self.snapshots), post_load_rounds=rounds,
            final_lag_zero=(zero_lag(self.snapshots[-1], self.keys)
                            if self.snapshots and lag_complete(self.snapshots[-1], self.keys) else None),
            post_load_zero_lag_confirmed_at=confirmed_at,
            load_ended_at=load_ended_at, drain_seconds_limit=self.drain_seconds,
            db_time_offset=self.db_time_offset,
            database_observed=database_observed, ai_log_observed=ai_log_observed,
            final_observation_cancelled=cancelled,
            latency_sources={
                "waf_access_at": "Nginx access log time(초 단위, 요청 시작 시각 아님)",
                "log_row_at": "network_logs.created_at을 명시한 DB 저장 시각 기준으로 UTC 변환(커밋 시각 아님)",
                "ai_handled_at": "서비스 반환 후 AI analysis result received 로그 시각",
                "clock_sync_verified": False},
            unmeasured=["정확한 요청 시작→커밋 지연", "정책상 제외·실패·DLT의 요청별 집계",
                        "알림 발송·브라우저 수신", "실제 차단"])
        self.write("pipeline-summary.json", result)
        return result
