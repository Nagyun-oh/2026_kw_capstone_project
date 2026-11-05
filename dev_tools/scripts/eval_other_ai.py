"""다른 AI 탐지 모델(사전학습 HF 분류기)을 우리 요청 데이터에 돌려 탐지·오탐을 재는 비교 도구. (T2 다른 AI+WAF head-to-head)

우리 AI·WAF와 같은 샘플·같은 가중 환산(run_pipeline_test의 weighted_rate)으로 계산해 직접 비교한다.
모델은 요청의 디코딩된 경로+쿼리+본문을 문자열로 받는다(우리 AI 피처가 보는 범위와 맞춤).
'공격' 클래스 인덱스는 몇 개 예제로 자동 판별한다(--mal-index로 고정 가능).

예:
    python eval_other_ai.py --model cssupport/mobilebert-sql-injection-detect \\
        --input dev_tools/datasets/sample-census.jsonl --out dev_tools/datasets/t2-dvwa/other-ai-census.md
"""
import argparse
import json
import sys
from pathlib import Path
from urllib.parse import unquote_plus

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_pipeline_test as rp

PAYLOAD = {"sqli", "xss", "cmd_injection", "path_traversal", "rfi", "upload_webshell", "command_injection"}


def req_text(s: dict, mode: str = "full") -> str:
    """모델 입력. full=우리 AI와 같은 범위(경로+쿼리+본문), payload=값만(경로·파라미터 이름 제외)."""
    if mode == "payload":
        vals = []
        for blob in (s.get("query") or "", s.get("body") or ""):
            for pair in unquote_plus(blob).split("&"):
                vals.append(pair.split("=", 1)[1] if "=" in pair else pair)
        return " ".join(v for v in vals if v).strip()[:2000]
    parts = [s.get("path") or "", unquote_plus(s.get("query") or ""), unquote_plus(s.get("body") or "")]
    return " ".join(p for p in parts if p).strip()[:2000]


@torch.no_grad()
def predict(texts, tok, model, device, bs=256):
    out = []
    for i in range(0, len(texts), bs):
        batch = texts[i:i + bs]
        enc = tok(batch, return_tensors="pt", truncation=True, max_length=256, padding=True).to(device)
        probs = torch.softmax(model(**enc).logits, dim=1)
        out.append(probs.cpu())
        if i % (bs * 20) == 0:
            print(f"  추론 {i}/{len(texts)}", flush=True)
    return torch.cat(out)


def find_mal_index(tok, model, device) -> int:
    mal = ["1' OR '1'='1' -- -", "admin' UNION SELECT username,password FROM users-- -",
           "'; DROP TABLE users;--", "1 OR 1=1"]
    ben = ["hello world", "the quick brown fox jumps", "search blue running shoes", "user profile settings page"]
    pm = predict(mal, tok, model, device)
    pb = predict(ben, tok, model, device)
    n = pm.shape[1]
    # 공격 예제에서 평균 확률이 높고 정상 예제에서 낮은 클래스 = 공격 인덱스
    score = [(pm[:, c].mean() - pb[:, c].mean()).item() for c in range(n)]
    idx = max(range(n), key=lambda c: score[c])
    print(f"공격 클래스 인덱스 추정: {idx} (클래스 수 {n}, 점수차 {[round(x,3) for x in score]})")
    return idx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--mal-index", type=int, default=-1)
    ap.add_argument("--benign-index", type=int, default=-1,
                    help="다중분류 모델의 정상 클래스 인덱스(미지정 시 라벨 이름에서 자동 탐지)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--base-rates", default="0.1,0.01")
    ap.add_argument("--text-mode", default="full", choices=["full", "payload"])
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"모델 로드: {args.model} → {device}", flush=True)
    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model).to(device).eval()
    import re
    id2label = model.config.id2label or {}
    n_labels = model.config.num_labels
    benign_idx = args.benign_index
    if benign_idx < 0:
        for i, lab in id2label.items():
            if re.search(r"normal|benign|safe|legit|clean|valid", str(lab), re.I):
                benign_idx = int(i); break
    multiclass = n_labels > 2 and benign_idx >= 0
    if multiclass:
        print(f"다중분류 {n_labels}개 라벨, 정상 클래스 {benign_idx}={id2label.get(benign_idx)} → 판정=argmax≠정상", flush=True)
        verdict_desc = f"argmax ≠ 정상('{id2label.get(benign_idx)}')"
    else:
        mal_idx = args.mal_index if args.mal_index >= 0 else find_mal_index(tok, model, device)
        verdict_desc = f"'공격' 클래스(idx {mal_idx}) 확률 ≥ {args.threshold}"

    samples = [json.loads(l) for l in open(args.input, encoding="utf-8") if l.strip()]
    if args.limit:
        samples = samples[:args.limit]
    texts = [req_text(s, args.text_mode) for s in samples]
    print(f"{len(texts)}건 추론 시작", flush=True)
    probs = predict(texts, tok, model, device)
    if multiclass:
        pred = probs.argmax(dim=1).tolist()
        mal_flags = [pc != benign_idx for pc in pred]
    else:
        mal_prob = probs[:, mal_idx].tolist()
        mal_flags = [p >= args.threshold for p in mal_prob]

    rows = []
    for s, flag in zip(samples, mal_flags):
        fams = s.get("label_families") or []
        rows.append({"label": s["label_binary"], "source": s["source"],
                     "family": fams[0] if fams else ("benign" if s["label_binary"] == 0 else "unlabeled"),
                     "mal": bool(flag)})

    population = rp.load_population(args.input)
    attacks = [r for r in rows if r["label"] == 1]
    benign = [r for r in rows if r["label"] == 0]
    base_rates = [float(v) for v in args.base_rates.split(",") if v.strip()]

    def rate(items):
        n = sum(r["mal"] for r in items)
        return rp.pct(n, len(items)) if items else "-"

    L = [f"# 다른 AI 탐지 비교: {args.model}", "",
         f"- 입력: 요청 {len(rows)}건 ({args.input.name}), 공격 {len(attacks)} · 정상 {len(benign)}",
         f"- 판정: {verdict_desc}",
         f"- 입력 텍스트: 디코딩된 경로+쿼리+본문", "",
         "## 전체 (단순 집계)",
         f"- 공격 탐지율: {rate(attacks)}",
         f"- 정상 오탐률: {rate(benign)}", ""]

    # SQLi 특화 모델이므로 SQLi 하위집합도 따로
    sqli = [r for r in attacks if r["family"] in ("sqli",)]
    if sqli:
        L += ["## SQLi 공격만", f"- SQLi 탐지율: {rate(sqli)} (n={len(sqli)})", ""]

    if population is not None:
        cell = lambda v: "-" if v is None else f"{100*v[0]:.1f}% ±{100*v[1]:.1f}"
        tpr = rp.weighted_rate(attacks, population, lambda r: r["mal"])
        fpr = rp.weighted_rate(benign, population, lambda r: r["mal"])
        fpr_clean = rp.weighted_rate(benign, population, lambda r: r["mal"], exclude_sources=("ecml",))
        L += ["## 원본 구성 환산 (우리 census 수치와 직접 비교용)",
              f"- 탐지율: {cell(tpr)}", f"- 오탐률: {cell(fpr)}", f"- 오탐률(ecml 제외): {cell(fpr_clean)}"]
        for b in base_rates:
            if tpr and fpr and (tpr[0]*b + fpr[0]*(1-b)) > 0:
                prec = 100*tpr[0]*b/(tpr[0]*b + fpr[0]*(1-b))
                L.append(f"- 정밀도(공격 {100*b:g}% 가정): {prec:.1f}%")
        L.append("")

    from collections import defaultdict
    for key, title in (("family", "공격 유형별"), ("source", "출처별(정상 오탐)")):
        groups = defaultdict(list)
        pool = attacks if key == "family" else benign
        for r in pool:
            groups[r[key]].append(r)
        L += [f"## {title}"]
        for name, items in sorted(groups.items()):
            L.append(f"- {name}: {rate(items)}")
        L.append("")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))
    print(f"\n저장: {args.out}")


if __name__ == "__main__":
    main()
