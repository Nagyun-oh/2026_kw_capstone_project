"""요청별 AI 앙상블 점수·판정을 뽑는다(샤딩/병렬용, ROC 없음 — 단일 클래스 샤드도 안전).

출력 jsonl: {sample_id, source, label, logit, rule_hit}. 판정(공격)=rule_hit or logit>=logit(0.965).
AI 이미지 안에서:
  docker run --rm --network none -e OMP_NUM_THREADS=2 -v "$PWD/AI_new:/AI_new:ro" -v "$PWD/dev_tools:/dev_tools" \\
    security-ai:local python /dev_tools/scripts/eval_ai_scores.py --input /dev_tools/.../shard.jsonl --out /dev_tools/.../scores.jsonl
"""
import argparse, json, sys, time
from pathlib import Path
import numpy as np

AI_DIR = Path("/AI_new") if Path("/AI_new").exists() else Path(__file__).resolve().parents[2] / "AI_new"
sys.path.insert(0, str(AI_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import joblib  # noqa: E402
import features_v2 as fv  # noqa: E402
import main  # noqa: E402
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


def main_run(a):
    t0 = time.time()
    load_models()
    w = main.ENSEMBLE_WEIGHTS / main.ENSEMBLE_WEIGHTS.sum()
    samples = [json.loads(l) for l in open(a.input, encoding="utf-8") if l.strip()]
    n = len(samples)
    p_trans = np.zeros(n); tree_X = []; schema_X = []; rule = np.zeros(n, bool)
    for i, s in enumerate(samples):
        item = rpt.ai_input(rpt.build_request(s, "x"))
        req = main.HttpRequest(**item)
        row = fv.build_feature_row(req.method, req.url_path, req.query_params, req.body_content, req.user_agent)
        tree_row = fv.build_feature_row(req.method, req.url_path, req.query_params, "", req.user_agent)
        schema_row = se.build_row(req.url_path, req.query_params, req.body_content, main.schema_dict)
        rule[i] = bool(fv.rule_hits(row)) or (len(req.user_agent) > main.USER_AGENT_LIMIT)
        tree_X.append(main.tree_to_vector(tree_row)); schema_X.append(se.to_vector(schema_row))
        p_trans[i] = float(main.transformer_runtime.predict(
            PredictRequest(log_id=None, **main._fit_predict_fields(req))).threat_score)
        if (i + 1) % 20000 == 0:
            print(f"  {a.tag} {i+1}/{n} ({time.time()-t0:.0f}s)", flush=True)
    p_tree = main.tree_model.predict_proba(np.vstack(tree_X))[:, 1]
    p_schema = main.schema_model.predict_proba(np.vstack(schema_X))[:, 1]
    logit = w[0] * main._logit(p_trans) + w[1] * main._logit(p_tree) + w[2] * main._logit(p_schema)
    with open(a.out, "w", encoding="utf-8") as fh:
        for i, s in enumerate(samples):
            fh.write(json.dumps({"sample_id": s["sample_id"], "source": s.get("source", "?"),
                                 "label": int(s["label_binary"]), "logit": round(float(logit[i]), 5),
                                 "rule_hit": bool(rule[i])}, ensure_ascii=False) + "\n")
    print(f"{a.tag} 완료 {n}건 → {a.out} ({time.time()-t0:.0f}s)", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tag", default="AI")
    main_run(ap.parse_args())
