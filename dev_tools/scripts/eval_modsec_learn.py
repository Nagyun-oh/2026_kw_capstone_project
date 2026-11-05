"""ModSec-Learn(pralab)의 사전학습 모델을 우리 요청에 적용해 SQLi 탐지·오탐을 재는다.

ModSec-Learn의 피처 = CRS SQLi 룰(942xxx) 49개의 발동 여부(이진 벡터). pymodsecurity 빌드 대신
우리 실험실 ModSecurity 컨테이너(wafs/, CRS 4.25.1)에 요청을 보내 감사 로그에서 룰 발동을
뽑아 같은 49차원 벡터를 만들고, 그들의 joblib 모델(rf/log_reg)로 판정한다.

비교군: 같은 부분표본에서 (1) 순수 CRS 차단(래블 403) (2) ModSec-Learn RF/LogReg.
우리 AI는 census 수치(T1 페이지)와 비교한다(같은 census 출처).

전제: wafs 실험실이 PL4로 떠 있어야 함(rf_pl4 피처 PL과 맞춤):
    LAB_BLOCKING_PL=4 LAB_DETECTION_PL=4 docker compose -f wafs/docker-compose.yml up -d modsecurity
"""
import argparse
import json
import random
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import joblib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_pipeline_test as rp


def parse_rule_hits(run_id: str, container: str, since: str) -> dict:
    """docker logs(RelevantOnly 감사 로그)에서 요청별 942xxx 룰 발동을 모은다."""
    out = subprocess.run(["docker", "logs", "--since", since, container],
                         capture_output=True, text=True, errors="replace")
    hits = defaultdict(set)
    for line in (out.stdout + out.stderr).splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            tx = json.loads(line)["transaction"]
        except Exception:
            continue
        headers = {k.lower(): v for k, v in (tx.get("request", {}).get("headers") or {}).items()}
        sid = headers.get("x-sample-id", "")
        if not sid.startswith(f"SID-{run_id}-"):
            continue
        key = sid.split("-", 2)[2]
        for m in tx.get("messages", []):
            rid = str((m.get("details") or {}).get("ruleId", ""))
            if rid.startswith("942"):
                hits[key].add(rid)
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=Path, required=True, help="modsec-learn 클론 경로")
    ap.add_argument("--input", type=Path, default=ROOT / "dev_tools/datasets/sample-census.jsonl")
    ap.add_argument("--waf-port", type=int, default=8090)
    ap.add_argument("--container", default="waf-lab-modsecurity-1")
    ap.add_argument("--n-attack", type=int, default=5000)
    ap.add_argument("--n-benign", type=int, default=5000)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--out", type=Path, default=ROOT / "dev_tools/datasets/t2-dvwa/other-ai-modsec-learn.md")
    args = ap.parse_args()

    crs_ids = json.load(open(args.repo / "data" / "crs_sqli_ids_4.0.0.json"))["rules_ids"]
    rf = joblib.load(args.repo / "data/models/rf_pl4.joblib")
    lr = joblib.load(args.repo / "data/models/log_reg_pl4_l2.joblib")
    idx_of = {rid: i for i, rid in enumerate(crs_ids)}
    print(f"ModSec-Learn 피처 {len(crs_ids)}개, 모델 rf_pl4·log_reg_pl4_l2 로드", flush=True)

    rng = random.Random(42)
    all_rows = [json.loads(l) for l in open(args.input, encoding="utf-8") if l.strip()]
    sqli = [s for s in all_rows if (s.get("label_families") or [None])[0] == "sqli"]
    benign = [s for s in all_rows if s["label_binary"] == 0]
    rng.shuffle(sqli); rng.shuffle(benign)
    subset = sqli[:args.n_attack] + benign[:args.n_benign]
    rng.shuffle(subset)
    print(f"부분표본: SQLi {min(len(sqli),args.n_attack)} + 정상 {min(len(benign),args.n_benign)} = {len(subset)}", flush=True)

    run_id = "r" + time.strftime("%m%d%H%M%S")
    requests_ = [rp.build_request(s, run_id) for s in subset]
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 5))
    statuses = rp.send_all(requests_, "localhost", args.waf_port, args.workers, "WAF 전송")
    time.sleep(3)
    hits = parse_rule_hits(run_id, args.container, since)
    print(f"룰 발동 수집: {len(hits)}건에 942xxx 매칭", flush=True)

    X = np.zeros((len(subset), len(crs_ids)))
    for i, s in enumerate(subset):
        for rid in hits.get(s["sample_id"], ()):
            if rid in idx_of:
                X[i, idx_of[rid]] = 1.0
    rf_pred = rf.predict(X).astype(bool)
    lr_pred = lr.predict(X).astype(bool)
    block = {"403", "406"}
    crs_block = np.array([st in block for st in statuses])

    rows = []
    for i, s in enumerate(subset):
        fams = s.get("label_families") or []
        rows.append({"label": s["label_binary"], "source": s["source"],
                     "family": fams[0] if fams else "benign",
                     "crs": bool(crs_block[i]), "rf": bool(rf_pred[i]), "lr": bool(lr_pred[i])})
    attacks = [r for r in rows if r["label"] == 1]
    ben = [r for r in rows if r["label"] == 0]

    def pct(items, k):
        n = sum(r[k] for r in items)
        return rp.pct(n, len(items)) if items else "-"

    L = [f"# ModSec-Learn(pralab) head-to-head: SQLi {len(attacks)} · 정상 {len(ben)}", "",
         "- 피처: 우리 CRS 실험실(ModSecurity, CRS 4.25.1, PL4)에서 추출한 942xxx 룰 발동 49차원",
         "- 모델: ModSec-Learn 사전학습 rf_pl4 / log_reg_pl4_l2 (CRS 4.0.0 피처로 학습 — 버전 차이는 한계)",
         "- 비교군: 순수 CRS PL4 차단(403) vs ModSec-Learn RF/LogReg. 우리 AI는 census 수치와 비교.", "",
         "## SQLi 탐지율",
         f"- 순수 CRS PL4 차단: {pct(attacks,'crs')}",
         f"- ModSec-Learn RF: {pct(attacks,'rf')}",
         f"- ModSec-Learn LogReg: {pct(attacks,'lr')}", "",
         "## 정상 오탐률",
         f"- 순수 CRS PL4 차단: {pct(ben,'crs')}",
         f"- ModSec-Learn RF: {pct(ben,'rf')}",
         f"- ModSec-Learn LogReg: {pct(ben,'lr')}", ""]
    gb = defaultdict(list)
    for r in ben:
        gb[r["source"]].append(r)
    L += ["## 출처별 정상 오탐 (RF)"]
    for name, items in sorted(gb.items()):
        L.append(f"- {name}: {pct(items,'rf')}")
    L += ["", f"- 전송 상태: {dict(Counter(s[:1]+'xx' if s.isdigit() else s for s in statuses))}"]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))
    print(f"\n저장: {args.out}")


if __name__ == "__main__":
    main()
