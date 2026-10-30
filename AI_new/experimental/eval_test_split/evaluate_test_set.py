# -*- coding: utf-8 -*-
"""
AI_new 트리+스키마 모델 held-out TEST 세트 독립 검증 스크립트
================================================================

목적: 팀원이 우리가 보고한 성능(트리 AUC/AP, 스키마 AUC/AP)을 학습에 전혀 쓰이지 않은
      test split로 직접 재현/검증할 수 있게 한다.

필요 파일 (이 스크립트와 같은 폴더, 혹은 --data-dir로 경로 지정):
  - model_bundle_tree_schema.pkl        (Kaggle에서 받은 것)
  - features_v2_TEST_ONLY.parquet       (train/validation/external_eval 제외, test 22만5822건만)
  - schema_features_TEST_ONLY.parquet   (위와 동일 test split, 스키마 원본 피처)

중요: 여기 test split은 features_v2_dataset.parquet/schema_features.parquet에 원래부터
있던 'split' 컬럼 값이 'test'인 행만 뽑은 것이다 -- 트리/스키마 모델 학습(train)에도,
임계값·앙상블 가중치 튜닝(validation)에도 전혀 쓰이지 않은, 모델이 한 번도 보지 못한
데이터다. 그래서 여기서 나온 점수가 "정직한" 성능 측정치다.

스키마 모델의 "정상 트래픽 사전(dictionary)"은 재구축하지 않고 pkl 안에 이미 저장된
것(학습 시점에 train+label==0으로 만든 것과 동일)을 그대로 재사용한다 -- 그래야 배포된
모델과 100% 동일한 조건으로 검증된다.

실행:
  pip install scikit-learn==1.8.0 pandas pyarrow numpy
  python evaluate_test_set.py
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    roc_auc_score, average_precision_score, f1_score,
    precision_score, recall_score, confusion_matrix,
)

# AI_new/features_v2.py의 FEATURES 순서와 완전히 동일해야 함 (tree_to_vector 재현)
TREE_FEATURES = [
    "method_encoded", "file_extension_encoded",
    "url_len", "query_len", "body_len", "total_len",
    "path_depth", "param_count", "max_param_value_len",
    "special_char_count", "special_char_ratio",
    "digit_ratio", "alpha_ratio", "encoded_char_count", "non_ascii_count",
    "sql_keyword_count", "sql_tautology", "sql_comment_count",
    "xss_keyword_count", "xss_event_handler",
    "path_traversal_count", "cmd_keyword_count", "cmd_metachar",
    "template_injection", "nosql_count",
    "ua_is_bot", "ua_empty", "has_body",
]

SCHEMA_FEATURES = [
    "path_known", "paramset_known", "log_path_freq", "log_paramset_freq",
    "n_unknown_params", "frac_unknown", "n_params", "max_val_len",
    "mean_val_len", "n_numeric_vals", "n_encoded_vals", "path_depth",
]


def build_tree_matrix(df: pd.DataFrame, vocab: dict) -> np.ndarray:
    """features_v2_TEST_ONLY.parquet의 u_ 컬럼(body 제외 조건, main.py의 실제 서빙 조건과
    동일 -- 2026-09-20 Codex 리뷰로 확정된 조건)에서 TREE_FEATURES 순서로 행렬을 만든다."""
    method_map = vocab["method"]
    ext_map = vocab["file_extension"]

    method_enc = df["u_method"].map(lambda m: method_map.get(m, method_map["__OTHER__"]))
    ext_enc = df["u_file_extension"].map(lambda e: ext_map.get(e, ext_map["__OTHER__"]))

    cols = {"method_encoded": method_enc, "file_extension_encoded": ext_enc}
    for f in TREE_FEATURES:
        if f in ("method_encoded", "file_extension_encoded"):
            continue
        cols[f] = df[f"u_{f}"]

    mat = np.column_stack([cols[f].to_numpy() for f in TREE_FEATURES]).astype(np.float32)
    return mat


def build_schema_matrix(df: pd.DataFrame, dictionary: dict) -> np.ndarray:
    """schema_features_TEST_ONLY.parquet(path/param_names/n_params/...) + pkl에 저장된
    정상 트래픽 사전(dictionary)으로 tune_schema_expert.py의 build_rows()와 동일한 12개
    피처를 만든다."""
    path_cnt = dictionary["path_cnt"]
    pset_cnt = dictionary["pset_cnt"]
    path_params = dictionary["path_params"]

    paths = df["path"].fillna("").values
    pnames_arr = df["param_names"].fillna("").values
    n_params_arr = df["n_params"].to_numpy().astype(np.int32)
    path_depth = df["path"].fillna("").apply(lambda p: max(0, p.count("/") - 1)).to_numpy()

    n = len(df)
    path_known = np.zeros(n, dtype=np.float32)
    paramset_known = np.zeros(n, dtype=np.float32)
    log_path_freq = np.zeros(n, dtype=np.float32)
    log_paramset_freq = np.zeros(n, dtype=np.float32)
    n_unknown_params = np.zeros(n, dtype=np.float32)
    frac_unknown = np.zeros(n, dtype=np.float32)

    for i in range(n):
        path, pnames, n_params = paths[i], pnames_arr[i], n_params_arr[i]
        pc = path_cnt.get(path, 0)
        path_known[i] = 1.0 if pc > 0 else 0.0
        log_path_freq[i] = np.log1p(pc)

        key = (path, pnames)
        psc = pset_cnt.get(key, 0)
        paramset_known[i] = 1.0 if psc > 0 else 0.0
        log_paramset_freq[i] = np.log1p(psc)

        known_names = path_params.get(path, set())
        req_names = set(pnames.split(",")) if pnames else set()
        n_unk = len(req_names - known_names)
        n_unknown_params[i] = n_unk
        frac_unknown[i] = (n_unk / n_params) if n_params > 0 else 0.0

    cols = {
        "path_known": path_known, "paramset_known": paramset_known,
        "log_path_freq": log_path_freq, "log_paramset_freq": log_paramset_freq,
        "n_unknown_params": n_unknown_params, "frac_unknown": frac_unknown,
        "n_params": n_params_arr.astype(np.float32),
        "max_val_len": df["max_val_len"].to_numpy().astype(np.float32),
        "mean_val_len": df["mean_val_len"].to_numpy().astype(np.float32),
        "n_numeric_vals": df["n_numeric_vals"].to_numpy().astype(np.float32),
        "n_encoded_vals": df["n_encoded_vals"].to_numpy().astype(np.float32),
        "path_depth": path_depth.astype(np.float32),
    }
    mat = np.column_stack([cols[f] for f in SCHEMA_FEATURES]).astype(np.float32)
    return mat


def report(name: str, y_true: np.ndarray, y_prob: np.ndarray, threshold: float, by_source=None):
    y_pred = (y_prob >= threshold).astype(int)
    auc = roc_auc_score(y_true, y_prob)
    ap = average_precision_score(y_true, y_prob)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    print(f"\n===== {name} (threshold={threshold}) =====")
    print(f"AUC={auc:.4f}  AP(PR-AUC)={ap:.4f}  F1={f1:.4f}  Precision={prec:.4f}  Recall={rec:.4f}")
    print(f"Confusion Matrix [[TN FP] [FN TP]]:\n{cm}")

    if by_source is not None:
        print("-- source별 AP --")
        for src in sorted(by_source.unique()):
            m = by_source == src
            if m.sum() < 2 or len(set(y_true[m])) < 2:
                continue
            src_ap = average_precision_score(y_true[m], y_prob[m])
            print(f"  {src:12s} n={m.sum():>7,}  AP={src_ap:.4f}")

    return {"auc": auc, "ap": ap, "f1": f1, "precision": prec, "recall": rec}


def main():
    ap_ = argparse.ArgumentParser()
    ap_.add_argument("--data-dir", default=".", help="pkl/parquet 파일들이 있는 폴더")
    args = ap_.parse_args()
    d = Path(args.data_dir)

    print("[LOAD] model_bundle_tree_schema.pkl ...")
    bundle = joblib.load(d / "model_bundle_tree_schema.pkl")
    tree_model = bundle["tree"]["model"]
    tree_vocab = bundle["tree"]["vocab"]
    tree_threshold = bundle["tree"]["threshold"]
    reported_tree_metrics = bundle["tree"].get("metrics")

    schema_model = bundle["schema"]["model"]
    schema_dict = bundle["schema"]["dictionary"]
    schema_threshold = bundle["schema"]["threshold"]
    reported_schema_metrics = bundle["schema"].get("metrics")

    print("[LOAD] features_v2_TEST_ONLY.parquet / schema_features_TEST_ONLY.parquet ...")
    main_test = pd.read_parquet(d / "features_v2_TEST_ONLY.parquet")
    schema_test = pd.read_parquet(d / "schema_features_TEST_ONLY.parquet")
    assert len(main_test) == len(schema_test), "두 test 파일의 행 수가 다릅니다"
    assert (main_test["split"].values == "test").all()
    print(f"  test rows = {len(main_test):,}  (label 1(공격)={int(main_test['label'].sum()):,}, "
          f"0(정상)={int((main_test['label']==0).sum()):,})")

    y_true = main_test["label"].to_numpy()
    source = main_test["source"]

    print("\n[PREDICT] 트리 모델 (u_ 조건, main.py 실제 서빙 조건과 동일) ...")
    tree_X = build_tree_matrix(main_test, tree_vocab)
    tree_prob = tree_model.predict_proba(tree_X)[:, 1]
    tree_result = report("TREE 단독", y_true, tree_prob, tree_threshold, source)

    print("\n[PREDICT] 스키마 모델 (pkl에 저장된 정상 트래픽 사전 재사용) ...")
    schema_X = build_schema_matrix(schema_test, schema_dict)
    schema_prob = schema_model.predict_proba(schema_X)[:, 1]
    schema_result = report("SCHEMA 단독", y_true, schema_prob, schema_threshold, source)

    print("\n" + "=" * 60)
    print("우리가 pkl에 미리 기록해둔(빌드 시점) 보고 수치와 비교:")
    print(f"  TREE   보고값: overall_auc_u={reported_tree_metrics['overall_auc_u']:.4f}  "
          f"overall_ap_u={reported_tree_metrics['overall_ap_u']:.4f}")
    print(f"  TREE   방금 재현: AUC={tree_result['auc']:.4f}  AP={tree_result['ap']:.4f}")
    print(f"  SCHEMA 보고값: overall_auc={reported_schema_metrics['overall_auc']:.4f}  "
          f"overall_ap={reported_schema_metrics['overall_ap']:.4f}")
    print(f"  SCHEMA 방금 재현: AUC={schema_result['auc']:.4f}  AP={schema_result['ap']:.4f}")
    print("(위 두 줄씩이 거의 똑같이 나오면 = 우리가 보고한 성능이 test set에서 정확히 재현된다는 뜻)")

    print("\n※ 참고: 트랜스포머는 이 스크립트에 포함되지 않았습니다. 트랜스포머는 원문 텍스트"
          "(method/url/query/body/user-agent)를 직접 읽는 구조라, 이 parquet(이미 숫자로"
          "요약된 피처)만으로는 검증할 수 없습니다. 트랜스포머까지 포함한 전체 3모델 앙상블"
          "점수를 검증하려면 raw 원문이 담긴 test.jsonl이 추가로 필요합니다 -- 필요하면"
          "요청해주세요, 준비해드리겠습니다.")

    out = {
        "n_test": int(len(main_test)),
        "tree": tree_result, "tree_reported_at_build_time": reported_tree_metrics,
        "schema": schema_result, "schema_reported_at_build_time": reported_schema_metrics,
    }
    with open(d / "eval_test_results.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n[SAVE] {d / 'eval_test_results.json'} 에 결과 저장 완료")


if __name__ == "__main__":
    main()
