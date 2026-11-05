import json, math
from pathlib import Path
BASE = Path("/home/js011007/project/2026_kw_capstone_project/dev_tools/datasets/evasion")
THR = math.log(0.965 / 0.035)
recs = [json.loads(l) for l in open(BASE / "evasion-samples.jsonl", encoding="utf-8")]
ai = {}
for l in open(BASE / "ai-scores.jsonl", encoding="utf-8"):
    d = json.loads(l); ai[d["sample_id"]] = d

def stats(kind):
    items = [r for r in recs if r["kind"] == kind]
    n = len(items)
    if not n: return None
    crs = sum(r["crs_blocked"] for r in items) / n
    det = rule = model = 0
    for r in items:
        a = ai.get(r["sample_id"])
        if not a: continue
        rh = a["rule_hit"]; md = a["logit"] >= THR
        det += (rh or md); rule += rh; model += md
    return {"n": n, "crs_block": crs, "ai_detect": det / n, "ai_rule_gate": rule / n, "ai_model": model / n}

seed = stats("seed"); mut = stats("mutation")
summ = json.loads((BASE / "summary.json").read_text())
L = ["# WAF-A-MoLE 회피 실험: CRS 우회 SQLi를 AI가 잡는가", "",
     f"- CRS가 막던 seed {summ['seeds_crs_blocked']}개 중 **{summ['bypass_found']}개({100*(summ['bypass_rate'] or 0):.0f}%)**에서 CRS 우회 변이 발견 (WAF-A-MoLE SqlFuzzer)",
     "", "| 집합 | 건수 | CRS 차단 | AI 탐지 | (규칙게이트) | (ML 모델) |", "|---|---|---|---|---|---|"]
for name, s in (("원본 seed", seed), ("CRS 우회 변이", mut)):
    if s:
        L.append(f"| {name} | {s['n']} | {100*s['crs_block']:.0f}% | **{100*s['ai_detect']:.0f}%** | {100*s['ai_rule_gate']:.0f}% | {100*s['ai_model']:.0f}% |")
L += ["",
      f"- 해석: 변이는 CRS를 {100*(1-(mut['crs_block'] if mut else 0)):.0f}% 우회(차단 {100*(mut['crs_block'] if mut else 0):.0f}%)하지만, "
      f"AI가 **{100*(mut['ai_detect'] if mut else 0):.0f}%** 탐지.",
      "- ML 모델 vs 규칙게이트 기여로 '정규식이 아닌 ML이 변이를 잡는지' 구분."]
(BASE / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("\n".join(L))
