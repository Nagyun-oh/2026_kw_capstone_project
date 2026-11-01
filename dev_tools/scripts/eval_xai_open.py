"""독립 공개셋(open_testset_v1)에서 XAI 설명 레이어를 재평가한다(캐시 불필요).

eval_xai_explanations.py의 함수를 재사용하되, 판정은 ai-scores.jsonl에서 인라인으로 정한다.
대상 = 모델 판정 탐지(규칙게이트 아님) = logit≥logit(0.965) and not rule_hit.
독립셋은 오탐이 ~0(모델 판정 정상 2건)이라 '신뢰도(오탐 분리)'는 측정 불가 — 충실도·커버리지·시간·전역 기여만.

AI 이미지 안에서:
  docker run --rm --network none --user "$(id -u):$(id -g)" -e OMP_NUM_THREADS=4 \\
    -v "$PWD/AI_new:/AI_new:ro" -v "$PWD/dev_tools:/dev_tools" security-ai:local \\
    python /dev_tools/scripts/eval_xai_open.py
"""
import json, math, random, sys, time
from pathlib import Path
import numpy as np

AI_DIR = Path("/AI_new") if Path("/AI_new").exists() else Path(__file__).resolve().parents[2] / "AI_new"
sys.path.insert(0, str(AI_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import eval_xai_explanations as xe  # noqa: E402  (load_models·baseline_values·delete·shap_top·model_inputs 재사용)
import features_v2 as fv  # noqa: E402
import main  # noqa: E402
import run_pipeline_test as rpt  # noqa: E402
import schema_expert as se  # noqa: E402
from security_ai.serving.schemas import PredictRequest  # noqa: E402

BASE = (AI_DIR.parent if AI_DIR.name == "AI_new" and (AI_DIR.parent / "dev_tools").exists()
        else Path("/")) / "dev_tools/datasets/open-testset"
if not BASE.exists():
    BASE = Path("/dev_tools/datasets/open-testset")
THR = math.log(0.965 / 0.035)


def main_run():
    t0 = time.time()
    samples = [json.loads(l) for l in open(BASE / "sample-open.jsonl", encoding="utf-8") if l.strip()]
    sc = {}
    for l in open(BASE / "ai-scores.jsonl", encoding="utf-8"):
        d = json.loads(l); sc[d["sample_id"]] = d
    explainer = xe.load_models()
    benign_items = [rpt.ai_input(rpt.build_request(s, "x")) for s in samples if s["label_binary"] == 0][:4000]
    base_tree, base_schema = xe.baseline_values(benign_items)
    print(f"기준값(정상 {len(benign_items)}건) 준비 ({time.time()-t0:.0f}s)", flush=True)

    cases, latencies = [], []
    for s in samples:
        d = sc.get(s["sample_id"])
        if d is None or not (d["logit"] >= THR and not d["rule_hit"]):
            continue
        item = rpt.ai_input(rpt.build_request(s, "x"))
        req, row, tree_row, schema_row = xe.model_inputs(item)
        if fv.rule_hits(row) or len(req.user_agent) > main.USER_AGENT_LIMIT:
            continue  # 규칙 판정 제외(모델 판정만)
        tree_x, schema_x = main.tree_to_vector(tree_row), se.to_vector(schema_row)
        p_trans = float(main.transformer_runtime.predict(
            PredictRequest(log_id=None, **main._fit_predict_fields(req))).threat_score)
        probas = [p_trans, float(main.tree_model.predict_proba(tree_x)[0][1]),
                  float(main.schema_model.predict_proba(schema_x)[0][1])]
        t = time.perf_counter()
        _, reason, explanation = explainer.explain(req, tree_row, tree_x, schema_row, schema_x, probas, [])
        latencies.append((time.perf_counter() - t) * 1000)
        cases.append({"label": s["label_binary"], "reason": reason, "explanation": explanation,
                      "logit": explanation["logit"], "probas": probas, "tree_x": tree_x, "schema_x": schema_x,
                      "tree_row": tree_row, "schema_row": schema_row, "req": req})
        if len(cases) % 2000 == 0:
            print(f"  설명 {len(cases)} ({time.time()-t0:.0f}s)", flush=True)
    n = len(cases)
    print(f"모델 판정 탐지 {n}건 (정상 {sum(c['label']==0 for c in cases)}건)", flush=True)

    rng = random.Random(42)
    faith = {}
    for k in (1, 2, 3):
        faith[f"shap_top{k}"] = xe.delete(cases, [xe.shap_top(c, k) for c in cases], base_tree, base_schema)
        runs = [xe.delete(cases, [rng.sample(xe.ALL_FEATURES, k) for _ in cases], base_tree, base_schema)
                for _ in range(3)]
        faith[f"random{k}"] = {"flip_rate": round(float(np.mean([r["flip_rate"] for r in runs])), 4),
                               "mean_logit_drop": round(float(np.mean([r["mean_logit_drop"] for r in runs])), 4)}
    cov = {"new_explanation_coverage": round(float(np.mean([bool(c["explanation"]["toward_attack"]) for c in cases])), 4),
           "new_top3_with_evidence": round(sum(any(i["evidence"] for i in c["explanation"]["toward_attack"][:xe.ee.TOP_K_REASON])
                                               for c in cases) / n, 4)}
    lat = {"p50": round(float(np.percentile(latencies, 50)), 2), "p95": round(float(np.percentile(latencies, 95)), 2)}
    sample_cases = rng.sample(cases, min(3000, n))
    contrib = np.array([np.concatenate(((p := explainer.decompose(c["tree_x"], c["schema_x"], c["probas"]))["tree"], p["schema"]))
                        for c in sample_cases])
    order = np.argsort(-np.abs(contrib).mean(axis=0))
    gtop = [{"feat": f"{xe.ALL_FEATURES[j][0]}:{xe.ALL_FEATURES[j][1]}", "mean_abs": round(float(np.abs(contrib[:, j]).mean()), 4)}
            for j in order[:10]]

    out = {"n_model_decided": n, "n_model_decided_fp": int(sum(c["label"] == 0 for c in cases)),
           "faithfulness": faith, "coverage": cov, "latency_ms": lat, "global_top": gtop,
           "note": "독립셋 오탐~0 → 신뢰도(오탐 분리)·검토표시 측정 불가", "elapsed": round(time.time() - t0)}
    (BASE / "xai-eval").mkdir(parents=True, exist_ok=True)
    (BASE / "xai-eval/results.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    L = ["# open_testset XAI 재평가 (모델 판정 탐지 {:,}건)".format(n), "",
         "## 충실도 (지목 피처를 정상 기준값으로 바꿨을 때 판정 뒤집힘)",
         "| 방법 | 판정 뒤집힘 | 평균 로짓 감소 |", "|---|---|---|"]
    for k in (1, 2, 3):
        L.append(f"| SHAP 상위 {k} | {faith[f'shap_top{k}']['flip_rate']:.1%} | {faith[f'shap_top{k}']['mean_logit_drop']:.2f} |")
        L.append(f"| 무작위 {k} | {faith[f'random{k}']['flip_rate']:.1%} | {faith[f'random{k}']['mean_logit_drop']:.2f} |")
    L += ["", f"- 커버리지: 설명 {cov['new_explanation_coverage']:.1%}, 상위3 근거문자열 {cov['new_top3_with_evidence']:.1%}",
          f"- explain() p50 {lat['p50']}ms · p95 {lat['p95']}ms",
          f"- 신뢰도(오탐 분리): 모델 판정 오탐 {out['n_model_decided_fp']}건 → 측정 불가",
          "", "## 전역 기여 상위"]
    L += [f"- {g['feat']} {g['mean_abs']:.3f}" for g in gtop]
    (BASE / "xai-eval/report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    print("\n저장:", BASE / "xai-eval")


if __name__ == "__main__":
    main_run()
