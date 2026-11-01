"""사용자 응답 지연(k6 CSV)과 컨테이너 자원 사용량(docker stats)을 조건(대상 × RPS)별로 집계한다.

usage: python3 dev_tools/load-test/analyze_latency.py dev_tools/datasets/load-test/latency [접미사]
  접미사를 주면 runs<접미사>.jsonl·stats<접미사>.log를 읽어 summary<접미사>.json에 쓴다(예: -control).
출력: 화면 요약 + <폴더>/summary.json (회차를 합친 p50·p95·p99, 회차별 범위, 요청 유형별 지연, 컨테이너별 CPU·메모리)
"""
import collections, csv, json, re, statistics, sys
from pathlib import Path

OUT = Path(sys.argv[1])
SUFFIX = sys.argv[2] if len(sys.argv) > 2 else ""      # 예: "-control" → runs-control.jsonl, stats-control.log
runs = [json.loads(line) for line in open(OUT / f"runs{SUFFIX}.jsonl", encoding="utf-8") if line.strip()]
runs = [r for r in runs if not r["name"].startswith("warm")]


def pctl(values, q):
    values = sorted(values)
    if not values:
        return float("nan")
    k = (len(values) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def read_k6(path):
    """http_req_duration 표본: (ms, status, kind)"""
    samples = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["metric_name"] != "http_req_duration":
                continue
            tags = dict(kv.split("=", 1) for kv in row["extra_tags"].split("&") if "=" in kv)
            samples.append((float(row["metric_value"]), row["status"], tags.get("kind", "?")))
    return samples


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
UNITS = {"B": 1 / 2**20, "KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "kB": 1e3 / 2**20, "MB": 1e6 / 2**20, "GB": 1e9 / 2**20}


def mem_mib(text):
    m = re.match(r"([\d.]+)\s*([A-Za-z]+)", text.split("/")[0].strip())
    return float(m.group(1)) * UNITS.get(m.group(2), 1) if m else float("nan")


def read_stats(path):
    rows = []
    for line in open(path, encoding="utf-8", errors="replace"):
        ts, _, rest = line.partition(" ")
        rest = ANSI.sub("", rest).strip()
        if not rest.startswith("{"):
            continue
        try:
            d = json.loads(rest)
            rows.append((float(ts), d["Name"], float(d["CPUPerc"].rstrip("%") or 0), mem_mib(d["MemUsage"])))
        except (ValueError, KeyError, json.JSONDecodeError):
            continue
    return rows


stats = read_stats(OUT / f"stats{SUFFIX}.log")
CONTAINERS = ["waf", "juiceshop", "waf-fluent-bit", "kafka", "zookeeper", "security-backend-local",
              "security-mysql", "security-ai-local"]

per_run = []
for r in runs:
    samples = read_k6(OUT / r["name"] / "raw.csv")
    durs = [d for d, _, _ in samples]
    status = collections.Counter(s for _, s, _ in samples)
    kinds = {}
    for kind in ("api", "static", "login"):
        ks = [d for d, _, k in samples if k == kind]
        kinds[kind] = {"n": len(ks), "p50": pctl(ks, .5), "p95": pctl(ks, .95)}
    # 자원: 실행 시작 5초 뒤 ~ 끝 2초 전(부하가 일정한 구간)
    t0, t1 = r["start"] + 5, r["end"] - 2
    res = {}
    for name in CONTAINERS:
        seg = [(c, mm) for t, n, c, mm in stats if n == name and t0 <= t <= t1]
        if seg:
            res[name] = {"cpu_mean": statistics.fmean(c for c, _ in seg), "cpu_max": max(c for c, _ in seg),
                         "mem_max": max(mm for _, mm in seg)}
    k6_seg = [c for t, n, c, _ in stats if n == f"k6-{r['name']}" and t0 <= t <= t1]
    processed = r["offsets_end"][2] - r["offsets_start"][2] if r["target"] == "waf" else 0
    per_run.append({**r, "n": len(durs), "status": dict(status), "p50": pctl(durs, .5), "p95": pctl(durs, .95),
                    "p99": pctl(durs, .99), "mean": statistics.fmean(durs) if durs else None, "kinds": kinds,
                    "resources": res, "k6_cpu": statistics.fmean(k6_seg) if k6_seg else None,
                    "ai_processed": processed,
                    "ai_rate": processed / (r["end"] - r["start"] + r["drain_s"]) if processed else None,
                    "_durs": durs, "_samples": samples})

print("실행별")
for r in per_run:
    bad = {k: v for k, v in r["status"].items() if k not in ("200", "401")}
    print(f"  {r['name']:16s} n={r['n']:5d} p50 {r['p50']:6.2f}ms p95 {r['p95']:6.2f}ms p99 {r['p99']:6.2f}ms"
          f"  비정상 응답 {bad or 0}  사전대기 {r['pre_wait_s']}s drain {r['drain_s']}s"
          + (f"  AI {r['ai_processed']}건 {r['ai_rate']:.1f}건/s" if r["ai_rate"] else ""))

summary = {}
print("\n조건별(3회 합산)")
for rate in (10, 50, 100):
    for target in ("direct", "waf"):
        group = [r for r in per_run if r["rate"] == rate and r["target"] == target]
        if not group:
            continue
        durs = [d for r in group for d in r["_durs"]]
        kinds = {kind: {"p50": pctl([d for r in group for d, _, k in r["_samples"] if k == kind], .5),
                        "p95": pctl([d for r in group for d, _, k in r["_samples"] if k == kind], .95)}
                 for kind in ("api", "static", "login")}
        res = {}
        for name in CONTAINERS:
            vals = [r["resources"][name] for r in group if name in r["resources"]]
            if vals:
                res[name] = {"cpu_mean": statistics.fmean(v["cpu_mean"] for v in vals),
                             "mem_max": max(v["mem_max"] for v in vals)}
        entry = {"reps": len(group), "n": len(durs), "p50": pctl(durs, .5), "p95": pctl(durs, .95),
                 "p99": pctl(durs, .99), "p95_range": [min(r["p95"] for r in group), max(r["p95"] for r in group)],
                 "p50_range": [min(r["p50"] for r in group), max(r["p50"] for r in group)],
                 "kinds": kinds, "resources": res,
                 "errors": sum(v for r in group for k, v in r["status"].items() if k not in ("200", "401")),
                 "drain_s": [r["drain_s"] for r in group],
                 "ai_rate": [round(r["ai_rate"], 2) for r in group if r["ai_rate"]]}
        summary[f"{target}-{rate}"] = entry
        print(f"  {target:6s} {rate:3d} RPS  {entry['reps']}회 n={entry['n']:6d}  p50 {entry['p50']:6.2f}ms"
              f" (회차 {entry['p50_range'][0]:.2f}~{entry['p50_range'][1]:.2f})  p95 {entry['p95']:6.2f}ms"
              f" (회차 {entry['p95_range'][0]:.2f}~{entry['p95_range'][1]:.2f})  p99 {entry['p99']:6.2f}ms"
              f"  오류 {entry['errors']}")
        print("      유형별 p50/p95: " + ", ".join(f"{k} {v['p50']:.1f}/{v['p95']:.1f}ms" for k, v in kinds.items()))
        print("      CPU 평균(%) " + ", ".join(f"{n.replace('security-', '').replace('-local', '')} {v['cpu_mean']:.1f}"
                                          for n, v in res.items()))
    d, w = summary.get(f"direct-{rate}"), summary.get(f"waf-{rate}")
    if d and w:
        print(f"  → WAF 추가 지연 {rate} RPS: p50 +{w['p50'] - d['p50']:.2f}ms, p95 +{w['p95'] - d['p95']:.2f}ms")
json.dump(summary, open(OUT / f"summary{SUFFIX}.json", "w"), ensure_ascii=False, indent=1)
