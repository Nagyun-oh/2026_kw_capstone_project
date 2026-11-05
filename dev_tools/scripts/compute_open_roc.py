import json, math
from pathlib import Path
import numpy as np
import pyarrow.parquet as pq

ROOT = Path("/home/js011007/project/2026_kw_capstone_project")
BASE = ROOT / "dev_tools/datasets/open-testset"
THR = math.log(0.965 / 0.035)
trapz = getattr(np, "trapezoid", None) or np.trapz

sc = [json.loads(l) for l in open(BASE / "ai-scores.jsonl", encoding="utf-8")]
sid = [d["sample_id"] for d in sc]
y = np.array([d["label"] for d in sc], np.int8)
logit = np.array([d["logit"] for d in sc], float)
rule = np.array([d["rule_hit"] for d in sc], bool)
src = np.array([d["source"] for d in sc])
w1 = {}
for l in open(BASE / "waf-pl1-status.jsonl", encoding="utf-8"):
    d = json.loads(l); w1[d["sample_id"]] = d["status"] in ("403", "406")
waf1 = np.array([w1.get(s, False) for s in sid])
fam_col = pq.read_table(str(ROOT / "dev_tools/datasets/open_testset_v1.parquet"), columns=["attack_family"]).column("attack_family").to_pylist()
fam = np.array([(fam_col[int(s[1:])] or "") for s in sid])

def roc(score, yy):
    o = np.argsort(-score, kind="mergesort"); s = score[o]; ys = yy[o].astype(float)
    P, N = ys.sum(), len(ys) - ys.sum()
    if P == 0 or N == 0: return None, None, None
    tp, fp = np.cumsum(ys), np.cumsum(1 - ys)
    d = np.r_[np.where(np.diff(s) != 0)[0], len(s) - 1]
    tpr = np.r_[0, tp[d] / P]; fpr = np.r_[0, fp[d] / N]
    return fpr, tpr, float(trapz(tpr, fpr))

def thin(fpr, tpr, n=3000):
    idx = np.unique(np.linspace(0, len(fpr) - 1, n).astype(int)) if len(fpr) > n else np.arange(len(fpr))
    return fpr[idx].round(6).tolist(), tpr[idx].round(6).tolist()

att, ben = y == 1, y == 0
gated = logit.copy(); gated[rule] = logit.max() + 1
fm, tm, auc_m = roc(logit, y)
fg, tg, auc_g = roc(gated, y)
ai_attack = rule | (logit >= THR)
by_source = {}
for name in sorted(set(src.tolist())):
    m = (src == name) | ben
    _, _, a = roc(gated[m], y[m])
    if a is not None: by_source[name] = round(a, 4)
out = {"input": "open_testset_v1", "n": int(len(y)), "attack": int(att.sum()), "benign": int(ben.sum()),
       "threshold": 0.965,
       "curves": {"model_only": {"auc": round(auc_m, 4), "fpr": thin(fm, tm)[0], "tpr": thin(fm, tm)[1]},
                  "model_plus_rule_gate": {"auc": round(auc_g, 4), "fpr": thin(fg, tg)[0], "tpr": thin(fg, tg)[1]}},
       "operating_point_0965": {"detection": round(float(ai_attack[att].mean()), 4), "fpr": round(float(ai_attack[ben].mean()), 4),
                                "model_only_detection": round(float((logit >= THR)[att].mean()), 4),
                                "model_only_fpr": round(float((logit >= THR)[ben].mean()), 4),
                                "rule_gate_detection": round(float(rule[att].mean()), 4),
                                "rule_gate_fpr": round(float(rule[ben].mean()), 4)},
       "auc_by_source": by_source}
(BASE / "roc.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"AUC model_only={auc_m:.4f} · gate={auc_g:.4f} · 운영점 {out['operating_point_0965']}")
print("출처별 AUC:", by_source)

# 공격 유형별 탐지 (WAF PL1 / AI / OR / AND)
oor = waf1 | ai_attack; oand = waf1 & ai_attack
L = ["# open_testset_v1 공격 유형별 탐지율 (WAF PL1 / AI / OR / AND)", "",
     "| 유형 | 건수 | WAF | AI | OR | AND |", "|---|---|---|---|---|---|"]
fams = [f for f in sorted(set(fam[att].tolist())) if f]
for f in fams:
    m = att & (fam == f); n = int(m.sum())
    L.append(f"| {f} | {n} | {100*waf1[m].mean():.1f}% | {100*ai_attack[m].mean():.1f}% | {100*oor[m].mean():.1f}% | {100*oand[m].mean():.1f}% |")
L += ["", "## 출처별 정상 오탐", "| 출처 | 정상건수 | WAF | AI | OR |", "|---|---|---|---|---|"]
for name in sorted(set(src[ben].tolist())):
    m = ben & (src == name); n = int(m.sum())
    L.append(f"| {name} | {n} | {100*waf1[m].mean():.2f}% | {100*ai_attack[m].mean():.2f}% | {100*oor[m].mean():.2f}% |")
(BASE / "by-type.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("\n" + "\n".join(L))
