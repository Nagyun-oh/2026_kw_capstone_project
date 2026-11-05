"""k6 구형/2.x summary 정규화와 보수적인 판정. 외부 명령은 실행하지 않는다."""
import math

EVALUATION_VERSION = "arrival-smoke-v3"


def normalize(summary):
    source = summary.get("results", {}).get("metrics")
    if source is None:
        source = summary.get("metrics")
    if isinstance(source, list):
        source = {m["name"]: m for m in source
                  if isinstance(m, dict) and isinstance(m.get("name"), str)}
    if not isinstance(source, dict):
        raise ValueError("지원하는 k6 metrics 형식이 아닙니다.")

    def value(name, key):
        metric = source.get(name, {})
        values = metric.get("values", {}) if isinstance(metric, dict) else {}
        number = values.get(key)
        if (isinstance(number, (int, float)) and not isinstance(number, bool)
                and math.isfinite(number) and number >= 0):
            return number
        return None

    return {
        "http_requests": value("http_reqs", "count"),
        "completed_iterations": value("iterations", "count"),
        "http_avg_ms": value("http_req_duration", "avg"),
        "http_p50_ms": value("http_req_duration", "med"),
        "http_p95_ms": value("http_req_duration", "p(95)"),
        "http_p99_ms": value("http_req_duration", "p(99)"),
        "http_max_ms": value("http_req_duration", "max"),
        "normal_ok_rate": value("normal_ok", "rate"),
        "dropped_iterations": value("dropped_iterations", "count"),
    }


def assess(measured, exit_code, observations_complete, state="COMPLETED"):
    """계획 건수 대신 실제 반복 완료·HTTP 결과·증거 확보로 예비 실험을 판정한다."""
    failures, unknowns = [], []
    checks = [
        ("http_requests", lambda x: x > 0, "실제 HTTP 요청이 없습니다."),
        ("completed_iterations", lambda x: x > 0, "완료된 반복이 없습니다."),
        ("normal_ok_rate", lambda x: x == 1, "HTTP 200 응답 비율이 100%가 아닙니다."),
        ("dropped_iterations", lambda x: x == 0, "실행하지 못한 반복이 있습니다."),
    ]
    for key, check, reason in checks:
        value = measured.get(key)
        if value is not None and not check(value):
            failures.append(reason)
    requests = measured.get("http_requests")
    iterations = measured.get("completed_iterations")
    if (state == "COMPLETED" and requests is not None and iterations is not None
            and requests != iterations):
        failures.append("실제 HTTP 요청 수와 완료된 반복 수가 다릅니다.")
    if exit_code == 99:
        failures.append("k6 임계값을 위반했습니다(종료 코드 99).")
    elif exit_code != 0:
        unknowns.append(f"k6 정상 종료를 확인하지 못했습니다(종료 코드 {exit_code}).")
    if state != "COMPLETED":
        unknowns.append(f"실행이 완료되지 않았습니다(state={state}).")
    required = ("http_requests", "completed_iterations", "http_avg_ms", "http_p95_ms",
                "http_p99_ms", "http_max_ms", "normal_ok_rate", "dropped_iterations")
    missing = [key for key in required if measured.get(key) is None]
    if missing:
        unknowns.append("필수 HTTP 지표가 없습니다: " + ", ".join(missing))
    if not observations_complete:
        unknowns.append("필수 결과 수집이 불완전합니다. 사건 기록과 원본 결과를 확인하세요.")
    verdict = "FAIL" if failures else "INCONCLUSIVE" if unknowns else "PASS"
    return {"verdict": verdict,
            "reasons": failures + unknowns or ["HTTP 응답·반복 완료·필수 수집 기준을 충족했습니다."]}


def judge(measured, exit_code, observations_complete, state="COMPLETED"):
    return assess(measured, exit_code, observations_complete, state)["verdict"]


def parse_lag(text):
    rows, header = [], None
    for line in text.splitlines():
        parts = line.split()
        if "GROUP" in parts and "TOPIC" in parts and "LAG" in parts:
            header = parts
            continue
        if not header or len(parts) < len(header):
            continue
        row = dict(zip(header, parts))
        try:
            rows.append({"group": row["GROUP"], "topic": row["TOPIC"],
                         "partition": int(row["PARTITION"]),
                         "lag": None if row["LAG"] == "-" else int(row["LAG"])})
        except (KeyError, ValueError):
            continue
    return rows


def resource_peaks(samples):
    result = {}
    for sample in samples:
        for row in sample["containers"]:
            name = row.get("Name", row.get("ID", "unknown"))
            item = result.setdefault(name, {"cpu_percent_max": None,
                                            "memory_percent_max": None})
            for source, target in [("CPUPerc", "cpu_percent_max"),
                                   ("MemPerc", "memory_percent_max")]:
                try:
                    number = float(row[source].removesuffix("%"))
                    if math.isfinite(number) and number >= 0:
                        old = item[target]
                        item[target] = number if old is None else max(old, number)
                except (KeyError, ValueError, TypeError):
                    pass
    return result

'''
- 역할: k6 결과 정규화 / lag 해석 / 자원 최대값 집계 및 판정
'''
