"""AI 판정 설명 레이어(AI_new/ensemble_explainer.py)를 census 표본으로 평가한다.

- 입력 : dev_tools/datasets/sample-census.jsonl, ai-cache.jsonl (run_pipeline_test.py 산출물, Git 제외)
         AI_new/models/*.pkl (scripts/fetch_models.py로 받는 배포 모델)
- 출력 : dev_tools/datasets/xai-eval/results.json, report.md (Git 제외)
- 대상 : AI가 공격으로 판정한 요청 중 규칙 게이트가 아니라 3모델이 판정한 것(모델 판정 탐지).
         규칙 판정은 규칙 자체가 근거라 평가하지 않는다.

평가 항목
1. 충실도(삭제 테스트): 설명이 지목한 피처를 '정상 기준값'(census 정상 요청의 중앙값, 이진·범주형은
   최빈값)으로 바꿨을 때 판정이 정상으로 뒤집히는 비율과 최종 로짓 감소량.
   SHAP 상위 k개 / 지금 reason이 언급한 피처 / 무작위 k개를 같은 탐지에서 비교한다.
   트랜스포머 확률은 고정한다(피처 단위 설명 대상이 아님).
2. 신뢰도 표시: 모델 판정 탐지 중 정상 라벨(오탐)과 공격 라벨(정탐)을 구분하는 정도.
   pattern_share(트리 기여 중 시그니처 피처 비율), 임계값 대비 여유 로짓, 트랜스포머 단독 확률의
   AUROC와 '검토 권장' 표시(pattern_share < 0.5, 미리 정한 기준)별 오탐 비율.
3. 커버리지·계산 시간: 근거 있는 설명을 받은 탐지 비율, explain() 1건 계산 시간.
4. 전역 기여도: 피처별 평균 |기여|(포스터용 전역 설명).

실행 (저장소 루트, AI 이미지에 shap이 설치된 상태에서):
    docker run --rm --network none --user "$(id -u):$(id -g)" \\
      -v "$PWD/AI_new:/AI_new:ro" -v "$PWD/dev_tools:/dev_tools" <AI 이미지> \\
      python /dev_tools/scripts/eval_xai_explanations.py
"""
import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AI_DIR = PROJECT_ROOT / "AI_new"
DATASET_DIR = PROJECT_ROOT / "dev_tools" / "datasets"
sys.path.insert(0, str(AI_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import joblib  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

import ensemble_explainer as ee  # noqa: E402
import features_v2 as fv  # noqa: E402
import main  # noqa: E402  (startup 훅은 실행되지 않는다 — Kafka에 붙지 않음)
import run_pipeline_test as rpt  # noqa: E402
import schema_expert as se  # noqa: E402
from security_ai.serving.predictor import ModelRuntime  # noqa: E402
from security_ai.serving.schemas import PredictRequest  # noqa: E402

# 지금 reason(features_v2.explain) 문구 → 그 문구를 만든 트리 피처
REASON_FEATURES = {
    "SQL 논리우회": ["sql_tautology"], "SQL 키워드": ["sql_keyword_count"],
    "SQL 주석 패턴": ["sql_comment_count"], "XSS 패턴": ["xss_keyword_count"],
    "XSS 이벤트 핸들러": ["xss_event_handler"], "디렉터리 탈출 패턴": ["path_traversal_count"],
    "커맨드 인젝션 패턴": ["cmd_keyword_count", "cmd_metachar"],
    "템플릿/JNDI 인젝션 패턴": ["template_injection"], "NoSQL 연산자": ["nosql_count"],
    "스캐너/봇 User-Agent": ["ua_is_bot"], "과도한 URL 인코딩": ["encoded_char_count"],
    "특수문자 과다": ["special_char_count"],
}
NO_EVIDENCE_REASON = "통계적 이상 (키워드 불일치 — 신뢰도 낮음)"
ALL_FEATURES = [("tree", f) for f in fv.FEATURES] + [("schema", f) for f in se.FEATURES]
TREE_INDEX = {f: i for i, f in enumerate(fv.FEATURES)}
SCHEMA_INDEX = {f: i for i, f in enumerate(se.FEATURES)}


def load_models():
    bundle = joblib.load(AI_DIR / "models" / "model_bundle_tree_schema.pkl")
    main.tree_model, main.tree_vocab = bundle["tree"]["model"], bundle["tree"]["vocab"]
    main.schema_model, main.schema_dict = bundle["schema"]["model"], bundle["schema"]["dictionary"]
    manifest = json.loads((AI_DIR / "models/transformer/model_bundle.pkl.manifest.json").read_text())
    main.transformer_runtime = ModelRuntime(
        AI_DIR / "models/transformer/model_bundle.pkl", taxonomy_path=AI_DIR / "models/attack_taxonomy.json",
        require_deployment=True, expected_artifact_sha256=manifest["bundle_sha256"])
    return ee.EnsembleExplainer(main.tree_model, main.schema_model, main.schema_dict,
                                main.ENSEMBLE_WEIGHTS, main.ENSEMBLE_THRESHOLD)


def model_inputs(item):
    """main.run_predict()와 같은 방식으로 세 모델 입력·확률을 만든다."""
    req = main.HttpRequest(**item)
    row = fv.build_feature_row(req.method, req.url_path, req.query_params, req.body_content, req.user_agent)
    tree_row = fv.build_feature_row(req.method, req.url_path, req.query_params, "", req.user_agent)
    schema_row = se.build_row(req.url_path, req.query_params, req.body_content, main.schema_dict)
    return req, row, tree_row, schema_row


def baseline_values(benign_items):
    """정상 요청의 피처 분포에서 피처별 기준값(중앙값, 0/1·범주형은 최빈값)."""
    tree_x = np.vstack([main.tree_to_vector(model_inputs(it)[2]) for it in benign_items])
    schema_x = np.vstack([se.to_vector(model_inputs(it)[3]) for it in benign_items])

    def pick(columns, categorical):
        values = []
        for j in range(columns.shape[1]):
            col = columns[:, j]
            if j in categorical or set(np.unique(col).tolist()) <= {0.0, 1.0}:
                values.append(Counter(col.tolist()).most_common(1)[0][0])
            else:
                values.append(float(np.median(col)))
        return np.array(values, dtype=np.float32)

    categorical = {TREE_INDEX["method_encoded"], TREE_INDEX["file_extension_encoded"]}
    return pick(tree_x, categorical), pick(schema_x, set())


def delete(cases, selections, base_tree, base_schema):
    """선택한 피처를 기준값으로 바꿔 다시 판정 → (뒤집힘 비율, 평균 로짓 감소)."""
    tree_x = np.vstack([c["tree_x"] for c in cases]).copy()
    schema_x = np.vstack([c["schema_x"] for c in cases]).copy()
    for i, chosen in enumerate(selections):
        for model, feature in chosen:
            if model == "tree":
                tree_x[i, TREE_INDEX[feature]] = base_tree[TREE_INDEX[feature]]
            else:
                schema_x[i, SCHEMA_INDEX[feature]] = base_schema[SCHEMA_INDEX[feature]]
    p_tree = main.tree_model.predict_proba(tree_x)[:, 1]
    p_schema = main.schema_model.predict_proba(schema_x)[:, 1]
    p_trans = np.array([c["probas"][0] for c in cases])
    w = main.ENSEMBLE_WEIGHTS / main.ENSEMBLE_WEIGHTS.sum()
    logits = w[0] * main._logit(p_trans) + w[1] * main._logit(p_tree) + w[2] * main._logit(p_schema)
    before = np.array([c["logit"] for c in cases])
    flipped = logits < ee._logit(np.float64(main.ENSEMBLE_THRESHOLD))
    return {"n": len(cases), "flip_rate": round(float(flipped.mean()), 4),
            "mean_logit_drop": round(float((before - logits).mean()), 4)}


def shap_top(case, k):
    return [(i["model"], i["feature"]) for i in case["explanation"]["toward_attack"][:k]]


def url_of(case):
    req = case["req"]
    return req.url_path + ("?" + req.query_params if req.query_params else "")


def waterfall_case(explainer, case, kind):
    """포스터용 지역 설명: 피처 40개의 기여를 모두 담은 분해 결과."""
    parts = explainer.decompose(case["tree_x"], case["schema_x"], case["probas"])
    items = []
    for model, names, values in (("tree", fv.FEATURES, parts["tree"]), ("schema", se.FEATURES, parts["schema"])):
        for name, contribution in zip(names, values):
            _, _, display = ee.describe(model, name, case["tree_row"], case["schema_row"])
            items.append({"model": model, "feature": name, "display": display,
                          "contribution": round(float(contribution), 4),
                          "pattern": model == "tree" and name in ee.PATTERN_FEATURES})
    items.sort(key=lambda item: -abs(item["contribution"]))
    return {"kind": kind, "label": case["label"], "method": case["req"].method, "url": url_of(case),
            "body": case["req"].body_content, "old_reason": case["old_reason"], "new_reason": case["reason"],
            "base_logit": round(parts["base_logit"], 4), "transformer": round(parts["transformer"], 4),
            "adjustment": round(parts["adjustment"], 6), "logit": round(parts["logit"], 4),
            "threshold_logit": round(explainer.threshold_logit, 4), "contributions": items}


def pick_examples(explainer, cases):
    """시그니처가 이끈 판정과 루트 경로(지름길)가 이끈 판정을 하나씩 고른다 (읽기 쉬운 짧은 요청 우선)."""
    top = lambda c: c["explanation"]["toward_attack"][0]["feature"]
    signature = [c for c in cases if c["label"] == 1 and not c["req"].body_content and top(c) == "sql_keyword_count"
                 and c["explanation"]["pattern_share"] >= 0.6 and len(url_of(c)) <= 80]
    shortcut = [c for c in cases if c["label"] == 1 and c["req"].method == "POST" and c["req"].body_content
                and top(c) == "path_depth" and c["old_reason"] != NO_EVIDENCE_REASON]
    examples = []
    if signature:
        examples.append(waterfall_case(explainer, min(signature, key=lambda c: (len(url_of(c)), url_of(c))), "signature"))
    if shortcut:
        examples.append(waterfall_case(explainer, min(shortcut, key=lambda c: (
            "../" not in c["req"].body_content, len(c["req"].body_content), c["req"].body_content)), "shortcut"))
    return examples


def reason_features(reason):
    return [("tree", f) for phrase, feats in REASON_FEATURES.items() if phrase in reason for f in feats]


def main_eval(args):
    t_start = time.time()
    cache = {}
    for line in open(DATASET_DIR / "ai-cache.jsonl", encoding="utf-8"):
        entry = json.loads(line)
        if "key" in entry:
            cache[entry["key"]] = entry["result"]

    detected, benign = [], []
    for line in open(DATASET_DIR / args.sample, encoding="utf-8"):
        sample = json.loads(line)
        item = rpt.ai_input(rpt.build_request(sample, "x"))
        result = cache.get(rpt.ai_key(item))
        if result is None:
            raise SystemExit("AI 캐시에 없는 요청이 있습니다. run_pipeline_test.py로 캐시를 먼저 채우세요.")
        if sample["label_binary"] == 0:
            benign.append(item)
        if result["ip_address"] != "0.0.0.0":
            detected.append((sample, item, result))
    print(f"표본 {len(benign)}건 정상 라벨, 탐지 {len(detected)}건", flush=True)

    explainer = load_models()
    base_tree, base_schema = baseline_values(benign)

    cases, rule_decided, latencies = [], 0, []
    for n, (sample, item, result) in enumerate(detected, start=1):
        req, row, tree_row, schema_row = model_inputs(item)
        if fv.rule_hits(row) or len(req.user_agent) > main.USER_AGENT_LIMIT:
            rule_decided += 1
            continue
        tree_x, schema_x = main.tree_to_vector(tree_row), se.to_vector(schema_row)
        p_trans = float(main.transformer_runtime.predict(
            PredictRequest(log_id=None, **main._fit_predict_fields(req))).threat_score)
        probas = [p_trans, float(main.tree_model.predict_proba(tree_x)[0][1]),
                  float(main.schema_model.predict_proba(schema_x)[0][1])]
        started = time.perf_counter()
        _, reason, explanation = explainer.explain(req, tree_row, tree_x, schema_row, schema_x, probas, [])
        latencies.append((time.perf_counter() - started) * 1000)
        cases.append({"label": sample["label_binary"], "old_reason": result["reason"], "reason": reason,
                      "explanation": explanation, "logit": explanation["logit"], "probas": probas,
                      "tree_x": tree_x, "schema_x": schema_x, "tree_row": tree_row, "schema_row": schema_row,
                      "req": req})
        if n % 5000 == 0:
            print(f"  설명 {n}/{len(detected)}", flush=True)
    print(f"모델 판정 {len(cases)}건, 규칙 판정 {rule_decided}건 ({time.time() - t_start:.0f}s)", flush=True)

    out = {"population": {"detected": len(detected), "model_decided": len(cases), "rule_decided": rule_decided,
                          "model_decided_label_1": sum(c["label"] == 1 for c in cases),
                          "model_decided_label_0": sum(c["label"] == 0 for c in cases),
                          # 운영 AI 판정을 다시 계산했을 때 임계값 아래로 나온 건수 (0이어야 정상)
                          "recomputed_below_threshold": sum(c["logit"] < c["explanation"]["threshold_logit"]
                                                            for c in cases)}}

    # 1. 충실도 — SHAP 상위 k vs 무작위 k (같은 탐지 전체)
    rng = random.Random(args.seed)
    faith = {}
    for k in (1, 2, 3):
        faith[f"shap_top{k}"] = delete(cases, [shap_top(c, k) for c in cases], base_tree, base_schema)
        runs = [delete(cases, [rng.sample(ALL_FEATURES, k) for _ in cases], base_tree, base_schema)
                for _ in range(args.random_repeats)]
        faith[f"random{k}"] = {"n": len(cases),
                               "flip_rate": round(float(np.mean([r["flip_rate"] for r in runs])), 4),
                               "mean_logit_drop": round(float(np.mean([r["mean_logit_drop"] for r in runs])), 4)}
    # 지금 reason과 같은 개수로 비교 (reason이 피처를 하나라도 언급한 탐지)
    cited = [(c, reason_features(c["old_reason"])) for c in cases]
    cited = [(c, feats) for c, feats in cited if feats]
    sized_shap = []
    for c, feats in cited:
        m = len(feats)
        if m <= len(c["explanation"]["toward_attack"]):
            sized_shap.append(shap_top(c, m))
        else:  # 상위 5개보다 많이 언급한 드문 경우 — 전체 기여 순위에서 고른다
            parts = explainer.decompose(c["tree_x"], c["schema_x"], c["probas"])
            contrib = [(float(v), ("tree", f)) for f, v in zip(fv.FEATURES, parts["tree"])]
            contrib += [(float(v), ("schema", f)) for f, v in zip(se.FEATURES, parts["schema"])]
            sized_shap.append([name for _, name in sorted(contrib, reverse=True)[:m]])
    cited_cases = [c for c, _ in cited]
    faith["same_size_as_reason"] = {
        "current_reason": delete(cited_cases, [feats for _, feats in cited], base_tree, base_schema),
        "shap": delete(cited_cases, sized_shap, base_tree, base_schema),
        "random": delete(cited_cases, [rng.sample(ALL_FEATURES, len(feats)) for _, feats in cited],
                         base_tree, base_schema),
        "mean_size": round(float(np.mean([len(feats) for _, feats in cited])), 2),
    }
    no_evidence = [c for c in cases if c["old_reason"] == NO_EVIDENCE_REASON]
    faith["no_evidence_reason_cases"] = {"n": len(no_evidence),
                                         "shap_top3": delete(no_evidence, [shap_top(c, 3) for c in no_evidence],
                                                             base_tree, base_schema)}
    out["faithfulness"] = faith

    # 2. 신뢰도 표시 — 오탐(정상 라벨) 구분
    labels = np.array([c["label"] for c in cases])
    share = np.array([c["explanation"]["pattern_share"] if c["explanation"]["pattern_share"] is not None
                      else 0.0 for c in cases])
    margin = np.array([c["logit"] - c["explanation"]["threshold_logit"] for c in cases])
    p_trans = np.array([c["probas"][0] for c in cases])
    flagged = np.array([c["explanation"]["review_recommended"] for c in cases])
    trans_agrees = p_trans >= main.transformer_runtime.threshold

    def fp_rate(mask):
        return round(float((labels[mask] == 0).mean()), 4) if mask.any() else None

    out["trust"] = {
        "auroc_label1": {"pattern_share": round(float(roc_auc_score(labels, share)), 4),
                         "margin_logit": round(float(roc_auc_score(labels, margin)), 4),
                         "transformer_probability": round(float(roc_auc_score(labels, p_trans)), 4)},
        "review_flag": {"flagged": int(flagged.sum()), "flag_rate": round(float(flagged.mean()), 4),
                        "fp_rate_flagged": fp_rate(flagged), "fp_rate_unflagged": fp_rate(~flagged),
                        "share_of_fp_flagged": round(float(flagged[labels == 0].mean()), 4),
                        "share_of_tp_flagged": round(float(flagged[labels == 1].mean()), 4),
                        "counts": {"flagged_tp": int((flagged & (labels == 1)).sum()),
                                   "flagged_fp": int((flagged & (labels == 0)).sum()),
                                   "unflagged_tp": int((~flagged & (labels == 1)).sum()),
                                   "unflagged_fp": int((~flagged & (labels == 0)).sum())}},
        "transformer_agrees": {"agrees": int(trans_agrees.sum()),
                               "fp_rate_agrees": fp_rate(trans_agrees), "fp_rate_disagrees": fp_rate(~trans_agrees)},
        "overall_fp_rate": fp_rate(np.ones_like(flagged, dtype=bool)),
    }

    # 3. 커버리지·시간
    with_evidence = sum(any(i["evidence"] for i in c["explanation"]["toward_attack"][:ee.TOP_K_REASON])
                        for c in cases)
    out["coverage"] = {
        "old_reason_no_evidence": len(no_evidence),
        "old_reason_coverage": round(1 - len(no_evidence) / len(cases), 4),
        "new_explanation_coverage": round(float(np.mean([bool(c["explanation"]["toward_attack"])
                                                         for c in cases])), 4),
        "new_top3_with_evidence_string": round(with_evidence / len(cases), 4),
        "reason_max_len": max(len(c["reason"]) for c in cases),
    }
    out["latency_ms"] = {"explain_p50": round(float(np.percentile(latencies, 50)), 2),
                         "explain_p95": round(float(np.percentile(latencies, 95)), 2),
                         "explain_p99": round(float(np.percentile(latencies, 99)), 2)}

    # 4. 전역 기여도 — 모델 판정 탐지 표본의 피처별 평균 |기여|, 평균 기여
    sample_cases = rng.sample(cases, min(args.global_sample, len(cases)))
    contrib = []
    for c in sample_cases:
        parts = explainer.decompose(c["tree_x"], c["schema_x"], c["probas"])
        contrib.append(np.concatenate([parts["tree"], parts["schema"]]))
    contrib = np.array(contrib)
    order = np.argsort(-np.abs(contrib).mean(axis=0))
    out["global_contribution"] = [
        {"model": ALL_FEATURES[j][0], "feature": ALL_FEATURES[j][1],
         "mean_abs": round(float(np.abs(contrib[:, j]).mean()), 4), "mean": round(float(contrib[:, j].mean()), 4)}
        for j in order[:15]]
    top1 = Counter(f"{c['explanation']['toward_attack'][0]['model']}:{c['explanation']['toward_attack'][0]['feature']}"
                   for c in cases if c["explanation"]["toward_attack"])
    out["top1_feature_share"] = {f: round(n / len(cases), 4) for f, n in top1.most_common(10)}
    out["examples"] = [{"label": c["label"], "old_reason": c["old_reason"], "new_reason": c["reason"]}
                       for c in rng.sample(cases, 8)]
    out["waterfall_examples"] = pick_examples(explainer, cases)
    # 그림용 피처 표시 이름(flag는 값이 1일 때 문구)과 시그니처형 피처 목록
    out["feature_labels"] = {f"{model}:{name}": label[0] if kind == "flag" else label
                             for model, table in (("tree", ee.TREE_FEATURES), ("schema", ee.SCHEMA_FEATURES))
                             for name, (label, kind) in table.items()}
    out["pattern_features"] = sorted(ee.PATTERN_FEATURES)
    out["elapsed_seconds"] = round(time.time() - t_start)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "results.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.out_dir / "report.md").write_text(render_report(out), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k not in ("examples", "global_contribution")},
                     ensure_ascii=False, indent=1))


def render_report(out):
    f, t, cov = out["faithfulness"], out["trust"], out["coverage"]
    lines = ["# AI 판정 설명 레이어 평가 (census 모델 판정 탐지)", "",
             f"- 대상: 모델 판정 탐지 {out['population']['model_decided']:,}건 "
             f"(정상 라벨 {out['population']['model_decided_label_0']:,}건), 규칙 판정 {out['population']['rule_decided']:,}건 제외",
             "", "## 1. 충실도 (지목한 피처를 정상 기준값으로 바꿨을 때)", "",
             "| 방법 | 판정 뒤집힘 | 평균 로짓 감소 |", "|---|---:|---:|"]
    for k in (1, 2, 3):
        lines.append(f"| SHAP 상위 {k} | {f[f'shap_top{k}']['flip_rate']:.1%} | {f[f'shap_top{k}']['mean_logit_drop']:.2f} |")
        lines.append(f"| 무작위 {k} | {f[f'random{k}']['flip_rate']:.1%} | {f[f'random{k}']['mean_logit_drop']:.2f} |")
    s = f["same_size_as_reason"]
    lines += ["", f"지금 reason이 피처를 언급한 {s['current_reason']['n']:,}건 (평균 {s['mean_size']}개, 같은 개수로 비교):", "",
              "| 방법 | 판정 뒤집힘 | 평균 로짓 감소 |", "|---|---:|---:|"]
    for name, key in (("지금 reason", "current_reason"), ("SHAP", "shap"), ("무작위", "random")):
        lines.append(f"| {name} | {s[key]['flip_rate']:.1%} | {s[key]['mean_logit_drop']:.2f} |")
    ne = f["no_evidence_reason_cases"]
    lines += ["", f"'통계적 이상' reason {ne['n']:,}건: SHAP 상위 3개 삭제 시 뒤집힘 {ne['shap_top3']['flip_rate']:.1%}", "",
              "## 2. 신뢰도 표시 (오탐 구분)", "",
              f"- 전체 오탐 비율: {t['overall_fp_rate']:.1%}",
              f"- AUROC (정탐을 높게): pattern_share {t['auroc_label1']['pattern_share']}, "
              f"여유 로짓 {t['auroc_label1']['margin_logit']}, 트랜스포머 확률 {t['auroc_label1']['transformer_probability']}",
              f"- 검토 권장 표시 {t['review_flag']['flagged']:,}건({t['review_flag']['flag_rate']:.1%}): "
              f"표시된 탐지 오탐 비율 {t['review_flag']['fp_rate_flagged']:.1%} vs 표시 안 된 탐지 {t['review_flag']['fp_rate_unflagged']:.1%}",
              f"- 오탐의 {t['review_flag']['share_of_fp_flagged']:.1%}, 정탐의 {t['review_flag']['share_of_tp_flagged']:.1%}에 표시",
              "", "## 3. 커버리지·계산 시간", "",
              f"- 지금 reason 커버리지 {cov['old_reason_coverage']:.1%} → 새 설명 {cov['new_explanation_coverage']:.1%}",
              f"- 상위 3개 중 근거 문자열이 있는 설명: {cov['new_top3_with_evidence_string']:.1%}",
              f"- explain() p50 {out['latency_ms']['explain_p50']}ms, p95 {out['latency_ms']['explain_p95']}ms",
              "", "## 4. 전역 기여도 상위 (평균 |기여|)", ""]
    lines += [f"- {g['model']}:{g['feature']} {g['mean_abs']:.3f} (평균 {g['mean']:+.3f})" for g in out["global_contribution"]]
    lines += ["", "## 예시", ""]
    lines += [f"- [라벨 {e['label']}] {e['old_reason']} → {e['new_reason']}" for e in out["examples"]]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sample", default="sample-census.jsonl", help="dev_tools/datasets 아래 표본 파일")
    parser.add_argument("--out-dir", type=Path, default=DATASET_DIR / "xai-eval")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--random-repeats", type=int, default=3)
    parser.add_argument("--global-sample", type=int, default=3000)
    main_eval(parser.parse_args())
