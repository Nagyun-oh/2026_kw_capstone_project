"""open_testset_v1(독립 공개셋) 판정 방식별 탐지 성능 표를 집계한다.

입력(dev_tools/datasets/open-testset/):
  ai-scores.jsonl       (eval_ai_scores.py 병합) — sample_id·label·logit·rule_hit
  waf-pl1-status.jsonl  (waf_pl_point --dump) — sample_id·status
  waf-pl4.json          (waf_pl_point) — PL4 집계
판정: AI 공격 = rule_hit or logit>=logit(0.965). WAF 탐지 = 403/406.
OR/AND = WAF(PL1) 와 AI 결합. 정밀도 = 가정 공격비율(10%)과 실제 비율 둘 다.
출력: report.md + table.json (같은 폴더)
"""
import json, math
from pathlib import Path

BASE = Path("dev_tools/datasets/open-testset")
THR = math.log(0.965 / (1 - 0.965))  # logit(0.965) ≈ 3.317

ai = {}
for l in open(BASE / "ai-scores.jsonl", encoding="utf-8"):
    d = json.loads(l)
    ai[d["sample_id"]] = (d["label"], bool(d["rule_hit"]) or d["logit"] >= THR)
waf1 = {}
for l in open(BASE / "waf-pl1-status.jsonl", encoding="utf-8"):
    d = json.loads(l)
    waf1[d["sample_id"]] = d["status"] in ("403", "406")
pl4 = json.loads((BASE / "waf-pl4.json").read_text(encoding="utf-8"))

att = ben = 0
acc = {"waf1": [0, 0], "ai": [0, 0], "or": [0, 0], "and": [0, 0]}  # [공격탐지, 정상탐지]
for sid, (lab, ia) in ai.items():
    w = waf1.get(sid, False)
    if lab == 1:
        att += 1
    else:
        ben += 1
    for key, val in (("waf1", w), ("ai", ia), ("or", w or ia), ("and", w and ia)):
        acc[key][0 if lab == 1 else 1] += int(val)

rate = lambda x, n: (x / n if n else 0.0)
ratio = att / (att + ben)


def prec(tpr, fpr, b):
    d = tpr * b + fpr * (1 - b)
    return tpr * b / d if d else 0.0


rows = [
    ("WAF PL1 (현재 설정)", rate(acc["waf1"][0], att), rate(acc["waf1"][1], ben)),
    ("WAF PL4", pl4["detection"], pl4["fpr"]),
    ("AI 단독", rate(acc["ai"][0], att), rate(acc["ai"][1], ben)),
    ("WAF OR AI (하나라도 탐지)", rate(acc["or"][0], att), rate(acc["or"][1], ben)),
    ("WAF AND AI (둘 다 탐지)", rate(acc["and"][0], att), rate(acc["and"][1], ben)),
]

out = {"n": att + ben, "attack": att, "benign": ben, "attack_ratio": round(ratio, 4), "rows": []}
L = [f"# open_testset_v1 판정 방식별 탐지 성능 (독립 공개셋 {att+ben:,}건)", "",
     f"- 공격 {att:,} · 정상 {ben:,} (공격 비율 {100*ratio:.1f}%) · 학습과 다른 출처(일반화 측정)",
     f"- AI 판정=rule_hit or logit≥logit(0.965). OR/AND=WAF(PL1)+AI. WAF=CRS 403 전수 집계.", "",
     "| 판정 방식 | 탐지율 | 오탐률 | 정밀도(공격 10%) | 정밀도(실제 " + f"{100*ratio:.1f}%) |",
     "|---|---|---|---|---|"]
for name, tpr, fpr in rows:
    p10 = prec(tpr, fpr, 0.10)
    pr = prec(tpr, fpr, ratio)
    L.append(f"| {name} | {100*tpr:.1f}% | {100*fpr:.1f}% | {100*p10:.1f}% | {100*pr:.1f}% |")
    out["rows"].append({"method": name, "detection": round(tpr, 4), "fpr": round(fpr, 4),
                        "precision_10pct": round(p10, 4), "precision_actual": round(pr, 4)})

(BASE / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
(BASE / "table.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
print("\n".join(L))
print("\n저장:", BASE / "report.md", "·", BASE / "table.json")
