"""탐지 지연(T4): AI가 공격으로 판정한 census 공격 샘플을 메인 WAF(localhost:80)로 일정 속도로 보내고
요청 시각 → Kafka 단계별 기록 시각 → 로그 저장(network_logs.created_at) → 위협 저장(detected_threats.detected_at)을 잰다.

usage:
  python3 dev_tools/load-test/detection_latency.py RUN_ID N RATE OUT_DIR   # 보내고 잰다
  python3 dev_tools/load-test/detection_latency.py --reanalyze OUT_DIR     # 저장된 latency.csv를 DB로 다시 집계
    RUN_ID  X-Sample-Id 접두어(SID-RUN_ID-sNNNNN), 실행마다 다르게
    N       보낼 샘플 수, RATE 초당 요청 수
보내는 쪽은 호스트(WAF가 보는 IP는 Docker 게이트웨이)라 블랙리스트 동기화에서 제외되고, 이미 등록돼 있어 새 행이 생기지 않는다.

위협은 종류별로 따로 잰다. 같은 요청을 CRS도 탐지하면 감사 로그 경로로 "WAF Detection" 위협이 AI보다 먼저 저장된다.

DB 시각: 백엔드는 UTC로 만든 LocalDateTime을 넘기지만 JDBC 주소의 serverTimezone=Asia/Seoul 때문에 DB에는
KST로 저장된다(앱이 읽을 때는 다시 UTC로 바뀐다). 그래서 created_at과 log-topic 기록 시각의 차이로 오프셋(30분 단위)을
구해 보정한다.
"""
import collections, csv, json, random, re, statistics, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dev_tools/scripts"))
import run_pipeline_test as m

D = ROOT / "dev_tools/datasets"
TOPICS = ("log-topic", "ai-request-topic", "ai-result-topic")
STAGES = [("WAF 기록·Fluent Bit 수집", "t0", "k_log"), ("백엔드 로그 소비·저장", "k_log", "t_saved"),
          ("AI 요청 발행", "t_saved", "k_ai_req"), ("AI 소비·추론", "k_ai_req", "k_ai_res"),
          ("AI 결과 소비·위협 저장", "k_ai_res", "t_ai_detected"), ("로그 저장까지", "t0", "t_saved"),
          ("AI 위협 저장까지", "t0", "t_ai_detected"), ("WAF 위협 저장까지", "t0", "t_waf_detected")]


def sh(*cmd, timeout=180):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout


def mysql(sql):
    return sh("docker", "exec", "security-mysql", "sh", "-c",
              'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -D security_db -N -B -e "$0"', sql)


def end_offsets():
    offsets = {}
    for line in sh("docker", "exec", "kafka", "kafka-run-class", "kafka.tools.GetOffsetShell",
                   "--bootstrap-server", "localhost:9092").splitlines():
        topic, _, off = line.rpartition(":")
        topic = topic.rpartition(":")[0]
        if topic in TOPICS:
            offsets[topic] = int(off)
    return offsets


def total_lag():
    lag = 0
    for line in sh("docker", "exec", "kafka", "kafka-consumer-groups", "--bootstrap-server", "localhost:9092",
                   "--describe", "--all-groups").splitlines():
        f = line.split()
        if len(f) > 5 and f[0].endswith("-group") and f[5].isdigit():
            lag += int(f[5])
    return lag


def read_topic(topic, start, count):
    """offset start부터 count개를 (기록 시각 ms, key, value)로 읽는다."""
    if count <= 0:
        return []
    text = sh("docker", "exec", "kafka", "kafka-console-consumer", "--bootstrap-server", "localhost:9092",
              "--topic", topic, "--partition", "0", "--offset", str(start), "--max-messages", str(count),
              "--timeout-ms", "20000", "--property", "print.timestamp=true", "--property", "print.key=true",
              timeout=600)
    records = []
    for line in text.splitlines():
        ts, _, rest = line.partition("\t")
        key, _, value = rest.partition("\t")
        if ts.startswith("CreateTime:"):
            records.append((int(ts.split(":")[1]), key, value))
    return records


def db_epoch(text):
    """DB DATETIME 문자열을 UTC로 읽은 epoch 초(시간대 보정 전)."""
    if text in ("NULL", "", None):
        return None
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()


def db_times(log_ids):
    """로그별 저장 시각과 위협 종류별 첫 저장 시각(보정 전 epoch)."""
    result = {}
    ids = sorted({int(i) for i in log_ids if i})
    for start in range(0, len(ids), 500):
        chunk = ",".join(map(str, ids[start:start + 500]))
        fmt = "'%Y-%m-%d %H:%i:%s.%f'"
        sql = (f"SELECT l.id, DATE_FORMAT(l.created_at,{fmt}), "
               f"DATE_FORMAT(MIN(CASE WHEN t.threat_type='AI Detection' THEN t.detected_at END),{fmt}), "
               f"DATE_FORMAT(MIN(CASE WHEN t.threat_type='WAF Detection' THEN t.detected_at END),{fmt}) "
               f"FROM network_logs l LEFT JOIN detected_threats t ON t.log_id=l.id WHERE l.id IN ({chunk}) GROUP BY l.id")
        for line in mysql(sql).splitlines():
            log_id, created, ai, waf = line.split("\t")
            result[log_id] = (db_epoch(created), db_epoch(ai), db_epoch(waf))
    return result


def apply_db_times(rows):
    """DB 시각을 붙이고, log-topic 기록 시각과의 차이로 DB 시간대 오프셋(30분 단위)을 구해 뺀다."""
    times = db_times(r["log_id"] for r in rows)
    diffs = [times[r["log_id"]][0] - r["k_log"] for r in rows if r["log_id"] in times and r["k_log"]]
    offset = round(statistics.median(diffs) / 1800) * 1800 if diffs else 0
    if offset:
        print(f"[note] DB 시각이 UTC보다 {offset / 3600:+.1f}시간 어긋나 보정했다(JDBC serverTimezone 영향).")
    for r in rows:
        saved, ai, waf = times.get(r["log_id"], (None, None, None))
        r["t_saved"] = saved - offset if saved else None
        r["t_ai_detected"] = ai - offset if ai else None
        r["t_waf_detected"] = waf - offset if waf else None
        r["db_offset_s"] = offset
    return rows


def pctl(values, q):
    values = sorted(values)
    if not values:
        return float("nan")
    k = (len(values) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def report(rows, out, meta):
    with open(out / "latency.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summary = {**meta, "n": len(rows), "saved": sum(r["t_saved"] is not None for r in rows),
               "ai_detected": sum(r["t_ai_detected"] is not None for r in rows),
               "waf_detected": sum(r["t_waf_detected"] is not None for r in rows), "stages": {}}
    print(f"\n로그 저장 {summary['saved']}/{len(rows)}, AI 위협 {summary['ai_detected']}/{len(rows)}, "
          f"WAF 위협 {summary['waf_detected']}/{len(rows)}")
    for name, a, b in STAGES:
        vals = [r[b] - r[a] for r in rows if r[a] is not None and r[b] is not None]
        st = {"n": len(vals), "mean": statistics.fmean(vals) if vals else None, "p50": pctl(vals, .5),
              "p95": pctl(vals, .95), "min": min(vals) if vals else None, "max": max(vals) if vals else None}
        summary["stages"][name] = st
        print(f"  {name:<20} n={st['n']:3d}  평균 {st['mean'] or 0:8.3f}s  p50 {st['p50']:8.3f}s  p95 {st['p95']:8.3f}s"
              f"  최소 {st['min'] or 0:8.3f}s  최대 {st['max'] or 0:8.3f}s")
    json.dump(summary, open(out / "summary.json", "w"), ensure_ascii=False, indent=1)


def measure(run_id, n, rate, out):
    # 1) 샘플 선택: 공격 라벨이고 AI가 공격으로 판정했으며 실험실 WAF가 정상 처리한(200/403) 요청 중
    #    로컬 DB request_url(varchar 255)에 들어가는 짧은 URI·작은 본문만 고른다.
    results = {r["sample_id"]: r for r in csv.DictReader(open(D / "census-modsecurity/results.csv", encoding="utf-8"))}
    eligible = []
    for s in m.load_samples(D / "sample-census.jsonl", 0):
        r = results[s["sample_id"]]
        if r["label"] != "1" or r["ai_attack"] != "True" or r["status"] not in ("200", "403"):
            continue
        req = m.build_request(s, run_id)
        if s["method"] in ("GET", "POST") and len(req["uri"]) <= 200 and len(req["body"]) <= 1000:
            eligible.append((s, req))
    picked = random.Random(7).sample(eligible, n)
    families = collections.Counter(s["label_families"][0] if s["label_families"] else "-" for s, _ in picked)
    print(f"후보 {len(eligible)}건 중 {n}건 선택:", dict(sorted(families.items())))

    max_log_id = int(mysql("SELECT COALESCE(MAX(id),0) FROM network_logs").strip())
    offsets0 = end_offsets()
    print("시작 offset:", offsets0, "network_logs max id:", max_log_id)

    # 2) 일정 간격으로 하나씩 보낸다(연결 재사용).
    sent = []
    t_start = time.time() + 0.5
    for i, (s, req) in enumerate(picked):
        delay = t_start + i / rate - time.time()
        if delay > 0:
            time.sleep(delay)
        t0 = time.time()
        status = m.send(req, "localhost", 80)
        sent.append({"sample_id": s["sample_id"], "family": (s["label_families"] or ["-"])[0], "method": s["method"],
                     "uri_len": len(req["uri"]), "status": status, "t0": t0, "t_resp": time.time()})
    print(f"전송 완료: {len(sent)}건, 응답 코드 {dict(collections.Counter(x['status'] for x in sent))}")

    # 3) 파이프라인이 다 처리할 때까지 기다린다(모든 소비 그룹 lag 0 + 여유 5초).
    t_wait = time.time()
    while time.time() - t_wait < 900 and total_lag() != 0:
        time.sleep(2)
    time.sleep(5)
    print(f"파이프라인 처리 대기 {time.time() - t_wait:.0f}s")

    # 4) Kafka 단계별 기록 시각과 요청별 log_id
    offsets1 = end_offsets()
    sid_re = re.compile(rf"SID-{re.escape(run_id)}-(s[0-9]+)")
    k_log = {}
    for ts, _, value in read_topic("log-topic", offsets0["log-topic"], offsets1["log-topic"] - offsets0["log-topic"]):
        hit = sid_re.search(value)
        if hit:
            k_log.setdefault(hit.group(1), ts)
    k_req = {key: ts for ts, key, _ in read_topic("ai-request-topic", offsets0["ai-request-topic"],
                                                   offsets1["ai-request-topic"] - offsets0["ai-request-topic"])}
    k_res = {key: ts for ts, key, _ in read_topic("ai-result-topic", offsets0["ai-result-topic"],
                                                   offsets1["ai-result-topic"] - offsets0["ai-result-topic"])}
    log_ids = {}
    sql = (f"SELECT REGEXP_SUBSTR(raw_log,'SID-{run_id}-s[0-9]+'), id FROM network_logs "
           f"WHERE id > {max_log_id} AND raw_log LIKE '%SID-{run_id}-%'")
    for line in mysql(sql).splitlines():
        sid, log_id = line.split("\t")
        log_ids[sid.split("-", 2)[2]] = log_id

    rows = []
    for x in sent:
        log_id = log_ids.get(x["sample_id"])
        kl, kq, kr = k_log.get(x["sample_id"]), k_req.get(log_id), k_res.get(log_id)
        rows.append({**x, "log_id": log_id, "k_log": kl / 1000 if kl else None,
                     "k_ai_req": kq / 1000 if kq else None, "k_ai_res": kr / 1000 if kr else None})
    report(apply_db_times(rows), out, {"run_id": run_id, "rate": rate, "offsets": [offsets0, offsets1]})


def reanalyze(out):
    """저장된 latency.csv의 요청·Kafka 시각을 그대로 두고 DB 시각만 다시 읽어 집계한다."""
    rows = []
    for r in csv.DictReader(open(out / "latency.csv", encoding="utf-8")):
        row = {k: r[k] for k in ("sample_id", "family", "method", "uri_len", "status")}
        for k in ("t0", "t_resp", "k_log", "k_ai_req", "k_ai_res"):
            row[k] = float(r[k]) if r.get(k) not in (None, "", "None") else None
        row["log_id"] = r["log_id"] or None
        rows.append(row)
    old = json.load(open(out / "summary.json", encoding="utf-8")) if (out / "summary.json").exists() else {}
    report(apply_db_times(rows), out, {k: old[k] for k in ("run_id", "rate", "offsets") if k in old})


if __name__ == "__main__":
    if sys.argv[1] == "--reanalyze":
        reanalyze(Path(sys.argv[2]))
    else:
        out_dir = Path(sys.argv[4])
        out_dir.mkdir(parents=True, exist_ok=True)
        measure(sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), out_dir)
