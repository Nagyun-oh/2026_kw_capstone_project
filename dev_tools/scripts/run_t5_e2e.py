"""T5: 파이프라인 무손실·장애 복구 검증 (WAF → Fluent Bit → Kafka → 백엔드 → AI → MySQL).

- E2E: 요청 N건을 보내고 다음을 확인한다(--repeat번 반복).
  1) 로그 저장: 보낸 요청마다 network_logs에 정확히 한 행이 생겼는가 (X-Sample-Id로 대조)
  2) AI 판정: 그 로그마다 ai-request-topic 요청과 ai-result-topic 결과가 정확히 한 건씩 오갔는가
  3) 위협 저장: AI가 공격으로 판정한 결과마다 detected_threats(AI Detection)에 한 행이 생겼는가
- 장애 복구: AI 컨테이너를 멈춘 채 N건을 보내 로그 저장과 AI 요청 적체를 확인하고, AI를 다시 켠 뒤 적체가 빠짐없이
  처리되는지와 걸린 시간을 잰다.

요청은 메인 스택 네트워크(security-net) 안의 일회용 컨테이너에서 WAF(waf:8080)로 보낸다. 호스트 IP가 차단 목록에
있으면 403이 섞일 수 있어서다. census 표본(URL 255자 초과 포함)에 긴 URL(1,000~4,000자) 요청을 섞는다.

- 전제: 루트 compose.yaml 스택 실행 중, dev_tools/datasets/sample-census.jsonl (sample_test_requests.py --mode census)
- 출력: dev_tools/datasets/t5/results.json, report.md (Git 제외)
- 주의: 요청이 메인 스택 DB(network_logs·detected_threats)에 시험 기록으로 남는다(X-Sample-Id: SID-t5...로 구분).
  장애 복구 단계는 AI 컨테이너(security-ai-local)를 멈췄다가 다시 켠다.

사용:
    python3 dev_tools/scripts/run_t5_e2e.py --repeat 3 --n 1000 --outage-n 300
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
D = ROOT / "dev_tools" / "datasets"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_pipeline_test as rpt  # noqa: E402

NETWORK, WAF_HOST, WAF_PORT = "security-net", "waf", 8080
MYSQL, KAFKA, AI, BACKEND = "security-mysql", "kafka", "security-ai-local", "security-backend-local"
SENDER_IMAGE = "security-ai:local"          # python만 있으면 되므로 AI 이미지를 빌려 쓴다
BOOTSTRAP = "kafka:29092"
GROUPS = ("log-group", "ai-service-group", "ai-result-group")
LONG_URL_LENGTHS = (1000, 2000, 4000)
KST_SHIFT = timedelta(hours=9)


def sh(cmd, timeout=300):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def sql(query):
    out = sh(["docker", "exec", MYSQL, "sh", "-c",
              'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -D security_db -N -B -e "$0"', query])
    if out.returncode:
        raise RuntimeError(out.stderr.strip())
    return [line.split("\t") for line in out.stdout.splitlines() if line]


def end_offset(topic):
    out = sh(["docker", "exec", KAFKA, "kafka-run-class", "kafka.tools.GetOffsetShell",
              "--broker-list", BOOTSTRAP, "--topic", topic, "--time", "-1"])
    return int(out.stdout.strip().split(":")[-1])


def lag(group):
    out = sh(["docker", "exec", KAFKA, "kafka-consumer-groups", "--bootstrap-server", BOOTSTRAP,
              "--describe", "--group", group])
    rows = [line.split() for line in out.stdout.splitlines()]
    lags = [int(r[5]) for r in rows if len(r) >= 6 and r[0] == group and r[5].isdigit()]
    return sum(lags) if lags else None


def read_topic(topic, start, end):
    """[start, end) 구간 메시지를 JSON으로 읽는다(파티션 1개 전제)."""
    if end <= start:
        return []
    out = sh(["docker", "exec", KAFKA, "kafka-console-consumer", "--bootstrap-server", BOOTSTRAP,
              "--topic", topic, "--partition", "0", "--offset", str(start),
              "--max-messages", str(end - start), "--timeout-ms", "20000"], timeout=180)
    messages = []
    for line in out.stdout.splitlines():
        try:
            messages.append(json.loads(line))
        except ValueError:
            pass
    return messages


def wait_idle(timeout=600):
    """이전 실행이 섞이지 않게 세 컨슈머 그룹의 대기열이 빌 때까지 기다린다."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        lags = {g: lag(g) for g in GROUPS}
        if all(v == 0 for v in lags.values()):
            return lags
        time.sleep(5)
    raise SystemExit(f"파이프라인 대기열이 비지 않습니다: {lags}")


def url_length(sample):
    query = sample.get("query") or ""
    return len(sample.get("path") or "") + (1 + len(query) if query else 0)


def make_requests(n, seed, long_n):
    samples = [json.loads(line) for line in open(D / "sample-census.jsonl", encoding="utf-8")]
    rng = random.Random(seed)
    chosen = rng.sample(samples, n - long_n)
    for i in range(long_n):
        length = LONG_URL_LENGTHS[i % len(LONG_URL_LENGTHS)]
        chosen.append({"sample_id": f"L{i:03d}", "label_binary": 0, "source": "t5-long", "label_families": [],
                       "method": "GET", "path": "/rest/products/search",
                       "query": "q=" + ("longurl" * (length // 7 + 1))[:length],
                       "headers": [["user-agent", "Mozilla/5.0 (T5 long-url check)"]], "body": "",
                       "content_type": None})
    rng.shuffle(chosen)
    return chosen


def send_in_container(run_dir, rate):
    """security-net 안의 일회용 컨테이너에서 이 스크립트의 send 단계를 실행한다."""
    cmd = ["docker", "run", "--rm", "--network", NETWORK, "--user", f"{os.getuid()}:{os.getgid()}",
           "-v", f"{ROOT / 'dev_tools'}:/dev_tools", SENDER_IMAGE, "python", "/dev_tools/scripts/run_t5_e2e.py",
           "send", "--run-dir", f"/dev_tools/datasets/t5/{run_dir.name}", "--rate", str(rate)]
    out = sh(cmd, timeout=3600)
    if out.returncode:
        raise SystemExit(f"전송 실패: {out.stderr[-2000:]}")
    return json.loads((run_dir / "sent.json").read_text(encoding="utf-8"))


def send_stage(args):
    """(컨테이너 안) requests.json의 요청을 일정 속도로 WAF에 보낸다."""
    run_dir = Path(args.run_dir)
    spec = json.loads((run_dir / "requests.json").read_text(encoding="utf-8"))
    interval = 1.0 / args.rate
    started = time.time()
    by_sid = {}
    for i, sample in enumerate(spec["samples"]):
        target = started + i * interval
        if target > time.time():
            time.sleep(target - time.time())
        by_sid[sample["sample_id"]] = rpt.send(rpt.build_request(sample, spec["run_id"]), WAF_HOST, WAF_PORT)
    (run_dir / "sent.json").write_text(json.dumps({
        "started": started, "finished": time.time(), "statuses": dict(Counter(by_sid.values())),
        "statuses_by_sid": by_sid}), encoding="utf-8")


def _stored_sids(run_id):
    rows = sql(f"SELECT REGEXP_SUBSTR(raw_log, 'SID-{run_id}-[A-Za-z0-9]+') FROM network_logs "
               f"WHERE raw_log LIKE '%SID-{run_id}-%'")
    return {r[0].split("-", 2)[2] for r in rows if r and r[0]}


def snapshot(run_id, sids, req_start, res_start):
    """이번 실행 요청의 로그·AI 요청·AI 결과·위협 저장 현황."""
    rows = sql(f"SELECT id, REGEXP_SUBSTR(raw_log, 'SID-{run_id}-[A-Za-z0-9]+') FROM network_logs "
               f"WHERE raw_log LIKE '%SID-{run_id}-%'")
    log_sid = {int(i): s.split("-", 2)[2] for i, s in rows if s}
    per_sid = Counter(log_sid.values())
    log_ids = set(log_sid)
    requests_ = [m for m in read_topic("ai-request-topic", req_start, end_offset("ai-request-topic"))
                 if m.get("log_id") in log_ids]
    results = [m for m in read_topic("ai-result-topic", res_start, end_offset("ai-result-topic"))
               if m.get("log_id") in log_ids]
    attack_ids = {m["log_id"] for m in results if m.get("ip_address") != "0.0.0.0"}
    threats = Counter()
    if log_ids:
        for log_id, count in sql("SELECT log_id, COUNT(*) FROM detected_threats WHERE threat_type='AI Detection' "
                                 f"AND log_id IN ({','.join(map(str, log_ids))}) GROUP BY log_id"):
            threats[int(log_id)] = int(count)
    return {
        "logs_stored": len(per_sid), "log_duplicates": sum(c - 1 for c in per_sid.values()),
        "missing_sids": sorted(set(sids) - set(per_sid))[:20],
        "ai_requests": len({m["log_id"] for m in requests_}), "ai_request_duplicates": len(requests_) - len({m["log_id"] for m in requests_}),
        "ai_results": len({m["log_id"] for m in results}), "ai_result_duplicates": len(results) - len({m["log_id"] for m in results}),
        "ai_attacks": len(attack_ids), "ai_with_explanation": sum(1 for m in results if m.get("explanation")),
        "threats_stored": len(set(threats) & attack_ids), "threat_duplicates": sum(c - 1 for c in threats.values()),
        "threats_without_attack_result": len(set(threats) - attack_ids),
        "long_urls_stored": sum(1 for s in per_sid if s.startswith("L")),
    }


def db_finish_times(run_id, since_epoch):
    """이번 실행의 마지막 로그·위협이 저장된 시각을 since_epoch(UTC) 기준 초로 돌려준다.

    백엔드는 UTC 시각을 넘기지만 JDBC serverTimezone=Asia/Seoul 때문에 DB에는 9시간 더해져 저장된다(테스트 계획 7번).
    """
    rows = sql(f"SELECT MAX(l.created_at), MAX(t.detected_at) FROM network_logs l LEFT JOIN detected_threats t "
               f"ON t.log_id=l.id AND t.threat_type='AI Detection' WHERE l.raw_log LIKE '%SID-{run_id}-%'")
    out = {}
    for key, value in zip(("last_log_s", "last_threat_s"), rows[0] if rows else []):
        if value and value != "NULL":
            stored = datetime.fromisoformat(value).replace(tzinfo=timezone.utc) - KST_SHIFT
            out[key] = round(stored.timestamp() - since_epoch, 1)
    return out


def wait_complete(run_id, sids, req_start, res_start, t0, timeout=1200, stall=60):
    """로그·결과·위협이 모두 모일 때까지(또는 더 늘지 않을 때까지) 기다리며 처음 다 모인 시각을 기록한다."""
    n = len(sids)
    deadline, last, last_change = time.time() + timeout, None, time.time()
    reached = {}
    while True:
        snap = snapshot(run_id, sids, req_start, res_start)
        now = time.time()
        for key, done in (("logs", snap["logs_stored"] >= n), ("ai_results", snap["ai_results"] >= n),
                          ("threats", snap["ai_results"] >= n and snap["threats_stored"] >= snap["ai_attacks"])):
            if done and key not in reached:
                reached[key] = round(now - t0, 1)
        if len(reached) == 3:
            return snap, reached
        progress = (snap["logs_stored"], snap["ai_results"], snap["threats_stored"])
        if progress != last:
            last, last_change = progress, now
        if now > deadline or now - last_change > stall:
            print(f"[warn] 더 늘지 않음: {progress} / {n}", flush=True)
            return snap, reached
        time.sleep(5)


def backend_errors(since):
    out = sh(["docker", "logs", "--since", since, BACKEND])
    text = out.stdout + out.stderr
    return {key: text.count(key) for key in ("Invalid AI result message", "Failed to save AI result",
                                              "LogEntry not found", "ERROR")}


def run_once(name, n, seed, long_n, rate, outage=False, outage_hold=20):
    run_id = f"t5{name}{datetime.now().strftime('%H%M%S')}"
    run_dir = D / "t5" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    samples = make_requests(n, seed, long_n)
    (run_dir / "requests.json").write_text(json.dumps({"run_id": run_id, "samples": samples}, ensure_ascii=False),
                                           encoding="utf-8")
    sids = [s["sample_id"] for s in samples]
    over_255 = sum(1 for s in samples if url_length(s) > 255)
    print(f"[{run_id}] 대기열 확인", flush=True)
    wait_idle()
    since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    req_start, res_start = end_offset("ai-request-topic"), end_offset("ai-result-topic")
    result = {"run_id": run_id, "n": n, "long_urls": long_n, "outage": outage}
    if outage:
        sh(["docker", "stop", AI], timeout=120)
        result["ai_stopped_at"] = time.time()
        print(f"[{run_id}] AI 중지", flush=True)
    print(f"[{run_id}] {n}건 전송 (초당 {rate}건)", flush=True)
    sent = send_in_container(run_dir, rate)
    result["http_statuses"], result["send_seconds"] = sent["statuses"], round(sent["finished"] - sent["started"], 1)
    t0 = sent["finished"]
    if outage:
        # AI가 꺼진 동안: 로그는 저장되고 AI 요청은 Kafka에 쌓여야 한다
        deadline = time.time() + 300
        while time.time() < deadline:
            snap = snapshot(run_id, sids, req_start, res_start)
            if snap["logs_stored"] >= n and snap["ai_requests"] >= n:
                break
            time.sleep(5)
        time.sleep(outage_hold)
        snap = snapshot(run_id, sids, req_start, res_start)
        result["during_outage"] = {"logs_stored": snap["logs_stored"], "ai_requests_queued": snap["ai_requests"],
                                   "ai_results": snap["ai_results"], "ai_service_lag": lag("ai-service-group")}
        sh(["docker", "start", AI], timeout=120)
        t_start = time.time()
        while time.time() - t_start < 300:
            health = sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", AI]).stdout.strip()
            if health == "healthy":
                break
            time.sleep(2)
        result["ai_restart_to_healthy_s"] = round(time.time() - t_start, 1)
        print(f"[{run_id}] AI 재기동 ({result['ai_restart_to_healthy_s']}초 뒤 healthy)", flush=True)
        t0 = t_start
    snap, reached = wait_complete(run_id, sids, req_start, res_start, t0)
    missing = [sent.get("statuses_by_sid", {}).get(sid, "?") for sid in sorted(set(sids) - _stored_sids(run_id))]
    result.update({"final": snap, "complete_after_s": reached, "backend_log_errors": backend_errors(since),
                   "lags_after": {g: lag(g) for g in GROUPS}, "missing_log_statuses": dict(Counter(missing)),
                   # E2E는 전송 끝, 장애 복구는 AI 재기동 시각 기준 (DB 저장 시각)
                   "finished_after_s": db_finish_times(run_id, t0)})
    result["urls_over_255"] = over_255
    (run_dir / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result["final"], ensure_ascii=False), flush=True)
    return result


def render_report(runs):
    lines = ["# T5 파이프라인 무손실·장애 복구 검증", "",
             "| 실행 | 보낸 요청 | 로그 저장 | 로그 없음(HTTP) | AI 결과 | AI 공격 판정 | 위협 저장 | 중복 | 마지막 위협 저장(초) |",
             "|---|---:|---:|---|---:|---:|---:|---:|---:|"]
    for r in runs:
        f = r["final"]
        dup = f["log_duplicates"] + f["ai_request_duplicates"] + f["ai_result_duplicates"] + f["threat_duplicates"]
        label = r["run_id"] + (" (AI 중지·재기동)" if r["outage"] else "")
        lines.append(f"| {label} | {r['n']:,} | {f['logs_stored']:,} | {r.get('missing_log_statuses', {})} | "
                     f"{f['ai_results']:,} | {f['ai_attacks']:,} | {f['threats_stored']:,} | {dup} | "
                     f"{r.get('finished_after_s', {}).get('last_threat_s', '-')} |")
    lines += ["", "- 마지막 위협 저장(초): E2E는 전송 끝, 장애 복구는 AI 재기동 시각부터 DB에 마지막 AI 위협이 저장될 때까지",
              "- 로그 없음: nginx가 URI 단계에서 400으로 거부한 요청(인코딩된 ../로 루트 위, %00 등)은 접근 로그에 남지 않아 "
              "파이프라인에 들어오지 않는다"]
    for r in runs:
        if r["outage"]:
            o = r["during_outage"]
            lines.append(f"- AI 중지 중: 로그 {o['logs_stored']:,}건 저장, AI 요청 {o['ai_requests_queued']:,}건 대기"
                         f"(결과 {o['ai_results']}건), 재기동 후 {r['ai_restart_to_healthy_s']}초에 healthy")
    lines.append(f"- HTTP 응답: {[r['http_statuses'] for r in runs]}")
    lines.append(f"- 백엔드 로그 오류: {[r['backend_log_errors'] for r in runs]}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd")
    s = sub.add_parser("send")
    s.add_argument("--run-dir", required=True)
    s.add_argument("--rate", type=float, default=20)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--n", type=int, default=1000)
    parser.add_argument("--long-n", type=int, default=12, help="E2E 실행마다 섞을 긴 URL 요청 수")
    parser.add_argument("--outage-n", type=int, default=300, help="0이면 장애 복구 단계를 건너뜀")
    parser.add_argument("--rate", type=float, default=20, help="초당 전송 건수")
    parser.add_argument("--out-dir", type=Path, default=D / "t5",
                        help="results.json·report.md 저장 위치. 이전 결과를 남기려면 실행마다 다르게 지정")
    args = parser.parse_args()
    if args.cmd == "send":
        return send_stage(args)
    runs = [run_once(f"e{i + 1}", args.n, 100 + i, args.long_n, args.rate) for i in range(args.repeat)]
    if args.outage_n:
        runs.append(run_once("out", args.outage_n, 200, 0, args.rate, outage=True))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "results.json").write_text(json.dumps(runs, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.out_dir / "report.md").write_text(render_report(runs), encoding="utf-8")
    print(render_report(runs))


if __name__ == "__main__":
    main()
