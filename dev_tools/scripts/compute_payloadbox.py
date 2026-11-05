import json, math
from collections import defaultdict
from pathlib import Path
BASE = Path("/home/js011007/project/2026_kw_capstone_project/dev_tools/datasets/payloadbox")
THR = math.log(0.965 / 0.035)
recs = {json.loads(l)["sample_id"]: json.loads(l) for l in open(BASE / "payloadbox-samples.jsonl", encoding="utf-8")}
waf = {}
for l in open(BASE / "waf-status.jsonl", encoding="utf-8"):
    d = json.loads(l); waf[d["sample_id"]] = d["status"] in ("403", "406")
ai = {}
for l in open(BASE / "ai-scores.jsonl", encoding="utf-8"):
    d = json.loads(l); ai[d["sample_id"]] = d

def aidet(sid):
    a = ai.get(sid)
    if not a: return (False, False, False)
    rh, md = a["rule_hit"], a["logit"] >= THR
    return (rh or md, rh, md)

ids = list(recs)
N = len(ids)
blk = [s for s in ids if waf.get(s, False)]
byp = [s for s in ids if not waf.get(s, False)]

def line(label, group):
    n = len(group)
    if not n: return f"| {label} | 0 | - | - | - | - |"
    waf_b = sum(waf.get(s, False) for s in group)
    det = sum(aidet(s)[0] for s in group); rule = sum(aidet(s)[1] for s in group); mod = sum(aidet(s)[2] for s in group)
    return f"| {label} | {n} | {100*waf_b/n:.0f}% | **{100*det/n:.0f}%** | {100*rule/n:.0f}% | {100*mod/n:.0f}% |"

L = ["# payload-box WAF 우회 payload 실험 (실제 공개 우회 payload)", "",
     f"- payload {N}건 (payload-box/waf-bypass-payload-list) → 쿼리 파라미터로 CRS(PL1)·AI 전수 통과",
     f"- CRS 차단 {len(blk)}건 / **CRS 우회(미차단) {len(byp)}건**", "",
     "| 집합 | 건수 | CRS 차단 | AI 탐지 | (규칙게이트) | (ML 모델) |", "|---|---|---|---|---|---|",
     line("전체", ids), line("**CRS 우회분**", byp), line("(CRS 차단분)", blk), "", "## 유형별 (전체)",
     "| 유형 | 건수 | CRS 차단 | AI 탐지 |", "|---|---|---|---|"]
bytype = defaultdict(list)
for s in ids: bytype[recs[s]["record_id"]].append(s)
for t, g in sorted(bytype.items(), key=lambda x: -len(x[1])):
    wb = sum(waf.get(s, False) for s in g); d = sum(aidet(s)[0] for s in g)
    L.append(f"| {t} | {len(g)} | {100*wb/len(g):.0f}% | {100*d/len(g):.0f}% |")
nb = len(byp)
L += ["", f"- **핵심: CRS를 우회한 {nb}건 중 AI가 {100*sum(aidet(s)[0] for s in byp)/max(nb,1):.0f}% 탐지**"
      f" (WAF 단독이면 0% — 이중방어가 회수).",
      "- 오탐은 별도 셋(open/독립셋)에서 ~0 확인, 여기선 탐지(회수)만 측정."]
(BASE / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("\n".join(L))
