"""확정된 로컬 성능 목표의 저장·검증·판정. 외부 서비스를 호출하지 않는다."""
import hashlib
import json
import math
from pathlib import Path

PROFILE = Path(__file__).parent / "profiles" / "local-load-v1.json"


def load_policy():
    raw = PROFILE.read_bytes()
    policy = json.loads(raw)
    if policy.get("version") != "local-load-v1":
        raise ValueError("지원하지 않는 성능 기준 버전")
    if policy.get("rates") != [1, 3, 5] or policy.get("seconds") != 120 or policy.get("drain_seconds") != 60:
        raise ValueError("확정된 부하·대기 범위와 프로필이 다릅니다.")
    for group in ("targets", "stop"):
        if not isinstance(policy.get(group), dict) or not policy[group]:
            raise ValueError("기준 필드가 없습니다.")
        for value in policy[group].values():
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError("기준 수치는 유한한 양수여야 합니다.")
    if not policy.get("required_services"):
        raise ValueError("필수 서비스 목록이 없습니다.")
    return policy, hashlib.sha256(raw).hexdigest()


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def assess_performance(policy, http, pipeline, abort=None, *, load_elapsed=None):
    failures, unknowns, checks = [], [], []
    if not finite(load_elapsed) or load_elapsed < policy["seconds"]:
        unknowns.append("설정한 120초의 실제 실행 구간을 확인하지 못했습니다.")

    def check(name, value, limit):
        status = "INCONCLUSIVE" if not finite(value) else "PASS" if value <= limit else "FAIL"
        checks.append(dict(metric=name, value=value, limit=limit, operator="<=", verdict=status))
        if status == "FAIL":
            failures.append(f"{name}={value}ms가 목표 {limit}ms를 초과했습니다.")
        elif status == "INCONCLUSIVE":
            unknowns.append(f"{name}를 판정할 증거가 없습니다.")

    for key in ("http_p95_ms", "http_p99_ms"):
        check(key, http.get(key), policy["targets"][key])
    stats = pipeline.get("latency_ms", {}).get("log_row_to_ai_handled", {})
    expected = http.get("http_requests")
    complete = finite(expected) and expected > 0 and stats.get("count") == expected
    for percentile in ("p95", "p99"):
        key = f"ai_handled_{percentile}_ms"
        check(key, stats.get(f"{percentile}_ms") if complete else None, policy["targets"][key])
    counts = pipeline.get("counts", {})
    for key in ("saved_logs", "distinct_request_ids", "ai_handled_logs"):
        value = counts.get(key)
        if not finite(expected) or not finite(value):
            unknowns.append(f"최종 {key} 대조 증거가 없습니다.")
        elif value != expected:
            # 완료 로그 부재는 실제 미처리·로그 유실을 구분할 증거가 더 필요하다.
            target = unknowns if key == "ai_handled_logs" or pipeline.get("final_observation_cancelled") else failures
            target.append(f"최종 {key}={value}, HTTP 요청 수={expected}로 일치하지 않습니다.")
    if pipeline.get("final_lag_zero") is False and not pipeline.get("final_observation_cancelled"):
        failures.append("최종 관측 기한까지 필수 Kafka 경로의 적체가 남았습니다.")
    elif not pipeline.get("post_load_zero_lag_confirmed_at"):
        unknowns.append("최종 연속 두 번의 lag 0 확인 증거가 없습니다.")
    if abort:
        (failures if abort["verdict"] == "FAIL" else unknowns).append(
            "자동 중단: " + abort["reason"])
    return dict(version=policy["version"], checks=checks,
                verdict="FAIL" if failures else "INCONCLUSIVE" if unknowns else "PASS",
                reasons=failures + unknowns or ["확정된 HTTP·비동기 지연·최종 처리 기준을 충족했습니다."])
