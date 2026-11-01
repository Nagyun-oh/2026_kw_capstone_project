"""전수 테스트셋으로 AI 앙상블의 ROC/AUC를 측정한다.

- 입력 : dev_tools/datasets/sample-raw-all.jsonl (flat 샘플, 225,822건)
         AI_new/models/*.pkl (scripts/fetch_models.py로 받는 배포 모델)
- 출력 : dev_tools/datasets/roc-auc/scores.jsonl (요청별 label·logit·규칙게이트)
         dev_tools/datasets/roc-auc/roc.json      (곡선별 fpr·tpr·AUC·운영점)
- 곡선 : (1) 3모델      = 앙상블 점수만 (규칙게이트 무시)
         (2) 3모델+규칙게이트 = 규칙 적중/UA 초과는 공격 확정(운영 AI 판정과 동일)
  운영 판정 = 규칙 적중 OR 로짓 ≥ logit(0.965). (2) 곡선의 임계값 운영점이 표1 'AI 단독'과 일치해야 한다.

AI 이미지(배포 의존성 포함) 안에서 실행:
    docker run --rm --network none --user "$(id -u):$(id -g)" \\
      -v "$PWD/AI_new:/AI_new:ro" -v "$PWD/dev_tools:/dev_tools" security-ai:local \\
      python /dev_tools/scripts/eval_roc_auc.py
"""
import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AI_DIR = PROJECT_ROOT / "AI_new"
DATASET_DIR = PROJECT_ROOT / "dev_tools" / "datasets"
sys.path.insert(0, str(AI_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import joblib  # noqa: E402
from sklearn.metrics import roc_auc_score, roc_curve  # noqa: E402

import features_v2 as fv  # noqa: E402
import main  # noqa: E402  (startup 훅은 실행되지 않는다 — Kafka에 붙지 않음)
import run_pipeline_test as rpt  # noqa: E402
import schema_expert as se  # noqa: E402
from security_ai.serving.predictor import ModelRuntime  # noqa: E402
from security_ai.serving.schemas import PredictRequest  # noqa: E402


def load_models():
    bundle = joblib.load(AI_DIR / "models" / "model_bundle_tree_schema.pkl")
    main.tree_model, main.tree_vocab = bundle["tree"]["model"], bundle["tree"]["vocab"]
    main.schema_model, main.schema_dict = bundle["schema"]["model"], bundle["schema"]["dictionary"]
    manifest = json.loads((AI_DIR / "models/transformer/model_bundle.pkl.manifest.json").read_text())
    main.transformer_runtime = ModelRuntime(
        AI_DIR / "models/transformer/model_bundle.pkl", taxonomy_path=AI_DIR / "models/attack_taxonomy.json",
        require_deployment=True, expected_artifact_sha256=manifest["bundle_sha256"])


def thin(fpr, tpr, n=3000):
    """로그 x축 ROC 플롯용으로 곡선을 n점 내외로 솎는다(양 끝 보존)."""
    if len(fpr) <= n:
        idx = np.arange(len(fpr))
    else:
        idx = np.unique(np.linspace(0, len(fpr) - 1, n).astype(int))
    return fpr[idx].round(6).tolist(), tpr[idx].round(6).tolist()


def main_eval(args):
    t0 = time.time()
    load_models()
    w = main.ENSEMBLE_WEIGHTS / main.ENSEMBLE_WEIGHTS.sum()
    thr_logit = float(main._logit(np.float64(main.ENSEMBLE_THRESHOLD)))

    samples = [json.loads(l) for l in open(DATASET_DIR / args.input, encoding="utf-8") if l.strip()]
    if args.limit:
        samples = samples[:args.limit]
    n = len(samples)
    print(f"{n}건 스코어링 시작 (가중 {w.round(3).tolist()}, 임계 로짓 {thr_logit:.3f})", flush=True)

    labels = np.zeros(n, np.int8)
    sources = []
    p_trans = np.zeros(n, np.float64)
    tree_X, schema_X = [], []
    rule_hit = np.zeros(n, bool)

    for i, s in enumerate(samples):
        item = rpt.ai_input(rpt.build_request(s, "x"))
        req = main.HttpRequest(**item)
        row = fv.build_feature_row(req.method, req.url_path, req.query_params, req.body_content, req.user_agent)
        tree_row = fv.build_feature_row(req.method, req.url_path, req.query_params, "", req.user_agent)
        schema_row = se.build_row(req.url_path, req.query_params, req.body_content, main.schema_dict)
        rule_hit[i] = bool(fv.rule_hits(row)) or (len(req.user_agent) > main.USER_AGENT_LIMIT)
        tree_X.append(main.tree_to_vector(tree_row))
        schema_X.append(se.to_vector(schema_row))
        p_trans[i] = float(main.transformer_runtime.predict(
            PredictRequest(log_id=None, **main._fit_predict_fields(req))).threat_score)
        labels[i] = int(s["label_binary"])
        sources.append(s.get("source", "?"))
        if (i + 1) % 10000 == 0:
            print(f"  {i+1}/{n}  ({time.time()-t0:.0f}s)", flush=True)

    print("트리·스키마 배치 추론...", flush=True)
    p_tree = main.tree_model.predict_proba(np.vstack(tree_X))[:, 1]
    p_schema = main.schema_model.predict_proba(np.vstack(schema_X))[:, 1]

    # 앙상블 로짓(운영 코드와 동일한 soft-vote)
    logit = w[0] * main._logit(p_trans) + w[1] * main._logit(p_tree) + w[2] * main._logit(p_schema)
    logit = np.asarray(logit, np.float64)

    # 규칙게이트 포함 점수: 규칙 적중은 모든 비적중보다 높게(공격 확정)
    gated = logit.copy()
    gated[rule_hit] = float(logit.max()) + 1.0

    attacks = labels == 1
    benign = labels == 0
    out = {
        "input": args.input, "n": int(n), "attack": int(attacks.sum()), "benign": int(benign.sum()),
        "ensemble_weights": w.round(4).tolist(), "threshold": main.ENSEMBLE_THRESHOLD,
        "elapsed_seconds": round(time.time() - t0),
        "curves": {}, "operating_point_0965": {}, "auc_by_source": {},
    }

    for name, score in (("model_only", logit), ("model_plus_rule_gate", gated)):
        auc = float(roc_auc_score(labels, score))
        fpr, tpr, _ = roc_curve(labels, score)
        f, t = thin(fpr, tpr)
        out["curves"][name] = {"auc": round(auc, 4), "fpr": f, "tpr": t}
        print(f"AUC [{name}] = {auc:.4f}", flush=True)

    # 운영 임계값(0.965) 운영점 — (2) 곡선 기준: 규칙 적중 OR 로짓≥임계
    decided = rule_hit | (logit >= thr_logit)
    out["operating_point_0965"] = {
        "detection": round(float(decided[attacks].mean()), 4),
        "fpr": round(float(decided[benign].mean()), 4),
        "model_only_detection": round(float((logit >= thr_logit)[attacks].mean()), 4),
        "model_only_fpr": round(float((logit >= thr_logit)[benign].mean()), 4),
        "rule_gate_detection": round(float(rule_hit[attacks].mean()), 4),
        "rule_gate_fpr": round(float(rule_hit[benign].mean()), 4),
    }

    # 출처별 AUC(규칙게이트 포함) — 정상은 전체 공통, 공격만 출처별로 비교
    src = np.array(sources)
    for name in sorted(set(sources)):
        m = (src == name) | benign  # 해당 출처 공격 + 전체 정상
        if labels[m].min() != labels[m].max():
            out["auc_by_source"][name] = round(float(roc_auc_score(labels[m], gated[m])), 4)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    with open(args.out_dir / "scores.jsonl", "w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(json.dumps({"sample_id": samples[i].get("sample_id"), "source": sources[i],
                                 "label": int(labels[i]), "logit": round(float(logit[i]), 5),
                                 "rule_hit": bool(rule_hit[i])}, ensure_ascii=False) + "\n")
    (args.out_dir / "roc.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "curves"}, ensure_ascii=False, indent=1), flush=True)
    print(f"\n저장: {args.out_dir}/roc.json , scores.jsonl  ({out['elapsed_seconds']}s)", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--input", default="sample-raw-all.jsonl", help="dev_tools/datasets 아래 flat 샘플")
    ap.add_argument("--out-dir", type=Path, default=DATASET_DIR / "roc-auc")
    ap.add_argument("--limit", type=int, default=0)
    main_eval(ap.parse_args())
