"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
model_selection_extreme.py — 극한의 하이퍼파라미터 튜닝 및 앙상블 구성
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[최적화 대상 모델 - 핵심 4대장]
  ① RandomForest   (안정성 극대화)
  ② ExtraTrees     (과적합 방지, 다양성 확보)
  ③ XGBoost        (NIDS 최고 성능 부스팅)
  ④ GradientBoosting (전통적 부스팅의 깊이 있는 패턴 탐지)

[극한 튜닝 모드 적용 사항]
  - 전체 Train 데이터 100% 학습 (서브셋 샘플링 제거)
  - Optuna N_TRIALS 대폭 증가 (기본 50회, 여유가 있다면 100회 권장)
  - 파라미터 탐색 공간(Search Space) 2~3배 확장
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import warnings
warnings.filterwarnings("ignore")

from pathlib import Path
from urllib.parse import unquote, urlparse
import re
import time

import joblib
import numpy as np
import pandas as pd
import optuna
optuna.logging.set_verbosity(optuna.logging.INFO) # 진행 상황을 보기 위해 INFO로 변경

from imblearn.combine import SMOTEENN
from sklearn.ensemble import (
    ExtraTreesClassifier, RandomForestClassifier,
    GradientBoostingClassifier
)

# 기존 GradientBoostingClassifier 지우고 아래로 교체
from sklearn.ensemble import HistGradientBoostingClassifier

from sklearn.metrics import (
    f1_score, roc_auc_score, accuracy_score,
    recall_score, confusion_matrix
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from scipy.optimize import minimize
from xgboost import XGBClassifier


# ════════════════════════════════════════════════════════════
# 0. 설정값 (Extreme Mode)
# ════════════════════════════════════════════════════════════
 
N_TRIALS     = 100      # 시간 여유가 주말 내내 있다면 100으로 올리셔도 됩니다. 평소에는 50.
RANDOM_STATE = 42
BASE_DIR     = Path(__file__).resolve().parent
BUNDLE_EXT   = BASE_DIR / "model_bundle_extreme.pkl"


# ════════════════════════════════════════════════════════════
# 1. 공통 상수 및 헬퍼 함수 (기존과 완벽히 동일)
# ════════════════════════════════════════════════════════════

ATTACK_KEYWORDS         = ["select","insert","update","delete","drop","union","exec","script","alert","../"]
SQL_KEYWORDS            = ["select","insert","update","delete","drop","union","where","from","exec","sleep","benchmark"]
XSS_KEYWORDS            = ["<script","script","alert","onerror","onload","javascript:","<img","<svg"]
PATH_TRAVERSAL_PATTERNS = ["../","..\\","%2e%2e","etc/passwd","boot.ini"]
SPECIAL_CHARS           = ["'",'"',"<",">","--",";","%","(",")",  "="]
#CATEGORICAL_COLUMNS     = ["method","user_agent","url_path","file_extension"]
CATEGORICAL_COLUMNS     = ["method","user_agent"]
FEATURES = [
    "method_encoded",
    "user_agent_encoded",
    #"url_path_encoded",     "file_extension_encoded",    "url_len",    "query_len",
    "body_len",
    #"total_len",    "path_depth",    "param_count",
    "special_char_count",
    "special_char_ratio",
    #"encoded_char_count",
    "digit_ratio",
    "alpha_ratio",
    #"has_keywords_query",
    "has_keywords_body",
    "sql_keyword_count",
    "xss_keyword_count",
    "path_traversal_count",
    "has_script_tag",
    "has_union_select",
    "has_comment_pattern",
]

def count_matches(text, patterns):
    t = (text or "").lower()
    return sum(t.count(p.lower()) for p in patterns)

def has_any(text, patterns):
    return int(count_matches(text, patterns) > 0)

def safe_ratio(part, total):
    return part / total if total else 0.0

def normalize_full_url(raw):
    if not raw: return "", ""
    parsed = urlparse(raw)
    path   = parsed.path or raw.split("?")[0]
    query  = parsed.query or (raw.split("?",1)[1] if "?" in raw else "")
    return path, query

def build_feature_row(method, url_path, query_params, body_content, user_agent, full_url=None):
    method       = (method or "UNKNOWN").upper()
    url_path     = url_path or ""
    query_params = query_params or ""
    body_content = "" if body_content in (None, "null") else body_content
    user_agent   = user_agent or ""
    visible_url  = full_url if full_url is not None else (url_path + (f"?{query_params}" if query_params else ""))
    decoded_q   = unquote(query_params)
    decoded_b   = unquote(body_content)
    combined    = f"{unquote(visible_url)} {decoded_b}"
    total_len   = len(visible_url) + len(body_content)
    scc = sum(visible_url.count(c) + body_content.count(c) for c in SPECIAL_CHARS)
    return {
        "method": method, "user_agent": user_agent, 
        #"url_path": url_path,        "file_extension": (Path(url_path).suffix.lower().lstrip(".") or "NONE"),
        #"url_len": len(visible_url), "query_len": len(query_params),
        "body_len": len(body_content), 
        #"total_len": total_len,
        #"path_depth": len([p for p in url_path.split("/") if p]),
        #"param_count": query_params.count("=") + body_content.count("="),
        "special_char_count": scc,
        "special_char_ratio": safe_ratio(scc, total_len),
        #"encoded_char_count": visible_url.count("%") + body_content.count("%"),
        "digit_ratio": safe_ratio(sum(c.isdigit() for c in visible_url + body_content), total_len),
        "alpha_ratio": safe_ratio(sum(c.isalpha() for c in visible_url + body_content), total_len),
        #"has_keywords_query":   has_any(decoded_q, ATTACK_KEYWORDS),
        "has_keywords_body":    has_any(decoded_b, ATTACK_KEYWORDS),
        "sql_keyword_count":    count_matches(combined, SQL_KEYWORDS),
        "xss_keyword_count":    count_matches(combined, XSS_KEYWORDS),
        "path_traversal_count": count_matches(combined, PATH_TRAVERSAL_PATTERNS),
        "has_script_tag":       int("<script" in combined.lower()),
        "has_union_select":     int("union" in combined.lower() and "select" in combined.lower()),
        "has_comment_pattern":  int("--" in combined or "/*" in combined or "*/" in combined),
    }

def parse_csic_file(file_path):
    with file_path.open("r", encoding="utf-8") as f: content = f.read()
    requests = re.findall(r"Start - Id:.*?\n(.*?)\nEnd - Id:", content, re.DOTALL)
    rows = []
    for req in requests:
        cls_match = re.search(r"class: (Valid|Attack)", req)
        label = 1 if cls_match and cls_match.group(1) == "Attack" else 0
        lines      = [l for l in req.splitlines() if l.strip()]
        first_line = next((l for l in lines if re.search(r"\b(GET|POST|PUT|DELETE)\b", l)), "")
        m  = re.search(r"\b(GET|POST|PUT|DELETE)\b", first_line)
        method = m.group(1) if m else "UNKNOWN"
        um = re.search(r"http://[^\s]+", first_line)
        full_url = um.group(0) if um else ""
        url_path, query_params = normalize_full_url(full_url)
        ua = re.search(r"User-Agent: (.*)", req)
        user_agent = ua.group(1).strip() if ua else ""
        body_content = ""
        if "\n\n" in req:
            body_content = req.split("\n\n", 1)[1].strip()
            if body_content == "null": body_content = ""
        row = build_feature_row(method, url_path, query_params, body_content, user_agent, full_url)
        row["class"] = label
        rows.append(row)
    return pd.DataFrame(rows)

def parse_capec_file(file_path):
    df_raw = pd.read_csv(file_path, low_memory=False)
    df_raw["class"] = (df_raw["000 - Normal"] == 0).astype(int)
    rows = []
    for _, r in df_raw.iterrows():
        method       = str(r.get("request_http_method") or "UNKNOWN").strip().upper()
        raw_request  = str(r.get("request_http_request") or "")
        body_content = "" if pd.isna(r.get("request_body")) else str(r["request_body"])
        user_agent   = "" if pd.isna(r.get("request_user_agent")) else str(r["request_user_agent"])
        url_path, query_params = normalize_full_url(raw_request)
        row = build_feature_row(method, url_path, query_params, body_content, user_agent, raw_request)
        row["class"] = int(r["class"])
        rows.append(row)
    return pd.DataFrame(rows)

def fit_encoder(series):
    enc = LabelEncoder()
    enc.fit(sorted(set(series.fillna("").astype(str).tolist()) | {"UNKNOWN"}))
    return enc

def apply_encoders(df, encoders):
    df = df.copy()
    for col, enc in encoders.items():
        known = set(enc.classes_)
        vals  = df[col].fillna("").astype(str).where(lambda s: s.isin(known), "UNKNOWN")
        df[f"{col}_encoded"] = enc.transform(vals)
    return df

def find_best_threshold(y_true, y_prob):
    best_t, best_f1 = 0.5, -1.0
    for t in np.arange(0.1, 0.91, 0.01):
        s = f1_score(y_true, (y_prob >= t).astype(int), zero_division=0)
        if s > best_f1: best_f1, best_t = s, float(round(t, 2))
    return best_t, best_f1


# ════════════════════════════════════════════════════════════
# 3. Optuna 극한 튜닝 함수 (100% 데이터 사용, 광범위 탐색)
# ════════════════════════════════════════════════════════════

def tune_random_forest(X_train, y_train, X_val, y_val):
    print(f"\n🌲 [1/4] RandomForest 튜닝 중 (N_TRIALS={N_TRIALS})...")
    def objective(trial):
        m = RandomForestClassifier(
            n_estimators     = trial.suggest_int("n_estimators", 100, 800), # 최대 800개 트리
            max_depth        = trial.suggest_int("max_depth", 10, 50),      # 한계 깊이 확장
            min_samples_split= trial.suggest_int("min_samples_split", 2, 20),
            min_samples_leaf = trial.suggest_int("min_samples_leaf", 1, 10),
            max_features     = trial.suggest_categorical("max_features", ["sqrt", "log2", None]),
            class_weight     ="balanced", random_state=RANDOM_STATE, n_jobs=-1,
        )
        m.fit(X_train, y_train) # 전체 데이터 사용
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS)
    p = study.best_params
    model = RandomForestClassifier(
        n_estimators=p["n_estimators"], max_depth=p["max_depth"],
        min_samples_split=p["min_samples_split"], min_samples_leaf=p["min_samples_leaf"],
        max_features=p["max_features"], class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model

def tune_extra_trees(X_train, y_train, X_val, y_val):
    print(f"\n🌳 [2/4] ExtraTrees 튜닝 중 (N_TRIALS={N_TRIALS})...")
    def objective(trial):
        m = ExtraTreesClassifier(
            n_estimators     = trial.suggest_int("n_estimators", 100, 800),
            max_depth        = trial.suggest_int("max_depth", 10, 50),
            min_samples_split= trial.suggest_int("min_samples_split", 2, 20),
            min_samples_leaf = trial.suggest_int("min_samples_leaf", 1, 10),
            max_features     = trial.suggest_categorical("max_features", ["sqrt", "log2"]),
            class_weight     ="balanced", random_state=RANDOM_STATE, n_jobs=-1,
        )
        m.fit(X_train, y_train)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS)
    p = study.best_params
    model = ExtraTreesClassifier(
        n_estimators=p["n_estimators"], max_depth=p["max_depth"],
        min_samples_split=p["min_samples_split"], min_samples_leaf=p["min_samples_leaf"],
        max_features=p["max_features"], class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model

def tune_xgboost(X_train, y_train, X_val, y_val):
    print(f"\n🚀 [3/4] XGBoost 튜닝 중 (N_TRIALS={N_TRIALS})...")
    spw = float((y_train == 0).sum()) / max(float((y_train == 1).sum()), 1)
    def objective(trial):
        m = XGBClassifier(
            n_estimators      = trial.suggest_int("n_estimators", 200, 1000), # 부스팅 트리 대폭 증가
            learning_rate     = trial.suggest_float("lr", 0.005, 0.2, log=True),
            max_depth         = trial.suggest_int("max_depth", 4, 15),
            subsample         = trial.suggest_float("subsample", 0.5, 1.0),
            colsample_bytree  = trial.suggest_float("colsample_bytree", 0.5, 1.0),
            gamma             = trial.suggest_float("gamma", 0.0, 5.0), # 과적합 방지 트리 가지치기
            min_child_weight  = trial.suggest_int("min_child_weight", 1, 15),
            scale_pos_weight  = spw, random_state=RANDOM_STATE,
            verbosity=0, eval_metric="logloss", n_jobs=-1, tree_method="hist" # 초고속 연산 모드
        )
        m.fit(X_train, y_train)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS)
    p = study.best_params
    model = XGBClassifier(
        n_estimators=p["n_estimators"], learning_rate=p["lr"], max_depth=p["max_depth"],
        subsample=p["subsample"], colsample_bytree=p["colsample_bytree"], gamma=p["gamma"],
        min_child_weight=p["min_child_weight"], scale_pos_weight=spw,
        random_state=RANDOM_STATE, verbosity=0, eval_metric="logloss", n_jobs=-1, tree_method="hist"
    )
    model.fit(X_train, y_train)
    return model

def tune_gradient_boosting(X_train, y_train, X_val, y_val):
    print(f"\n🏎️  [4/4] GradientBoosting 튜닝 중 (N_TRIALS={N_TRIALS})...")
    # GBM은 멀티코어(n_jobs) 지원이 약해 가장 오래 걸립니다.
    def objective(trial):
        m = GradientBoostingClassifier(
            n_estimators  = trial.suggest_int("n_estimators", 150, 500),
            learning_rate = trial.suggest_float("lr", 0.01, 0.2, log=True),
            max_depth     = trial.suggest_int("max_depth", 4, 10),
            subsample     = trial.suggest_float("subsample", 0.5, 1.0),
            random_state  = RANDOM_STATE,
        )
        m.fit(X_train, y_train)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS)
    p = study.best_params
    model = GradientBoostingClassifier(
        n_estimators=p["n_estimators"], learning_rate=p["lr"],
        max_depth=p["max_depth"], subsample=p["subsample"], random_state=RANDOM_STATE,
    )
    model.fit(X_train, y_train)
    return model

def tune_hist_gradient_boosting(X_train, y_train, X_val, y_val):
    print(f"\n🏎️  [4/4] HistGradientBoosting 튜닝 중 (N_TRIALS={N_TRIALS})...")
    # HistGradientBoosting은 기존 GBM보다 파라미터 이름이 조금 다릅니다.
    def objective(trial):
        m = HistGradientBoostingClassifier(
            max_iter          = trial.suggest_int("max_iter", 200, 800), # n_estimators와 동일
            learning_rate     = trial.suggest_float("lr", 0.01, 0.2, log=True),
            max_depth         = trial.suggest_int("max_depth", 8, 20),
            min_samples_leaf  = trial.suggest_int("min_samples_leaf", 10, 100),
            l2_regularization = trial.suggest_float("l2_regularization", 0.0, 5.0), # 과적합 방지
            random_state      = RANDOM_STATE,
            early_stopping    = False # 극한 튜닝을 위해 조기종료 끔
        )
        m.fit(X_train, y_train)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS)
    p = study.best_params
    model = HistGradientBoostingClassifier(
        max_iter=p["max_iter"], learning_rate=p["lr"],
        max_depth=p["max_depth"], min_samples_leaf=p["min_samples_leaf"],
        l2_regularization=p["l2_regularization"], random_state=RANDOM_STATE, early_stopping=False
    )
    model.fit(X_train, y_train)
    return model


# ════════════════════════════════════════════════════════════
# 4. 앙상블 및 평가 헬퍼 함수
# ════════════════════════════════════════════════════════════

def optimize_weights(proba_dict: dict, y_val: pd.Series) -> dict:
    names  = list(proba_dict.keys())
    probas = [proba_dict[n] for n in names]
    def objective(weights):
        w = np.abs(weights) / np.abs(weights).sum()
        combined = sum(wi * pi for wi, pi in zip(w, probas))
        return -max(f1_score(y_val, (combined >= t).astype(int), zero_division=0) for t in np.arange(0.3, 0.8, 0.05))
    result = minimize(objective, np.ones(len(names)) / len(names), method="Nelder-Mead", options={"maxiter": 5000, "xatol": 1e-6})
    w = np.abs(result.x) / np.abs(result.x).sum()
    return {name: round(float(wi), 4) for name, wi in zip(names, w)}

def print_table(val_probas, y_true):
    print("\n" + "=" * 80)
    print(f"{'순위':<4} {'모델':<20} {'Val F1':<10} {'AUC-ROC':<10} {'Recall':<10} {'FNR':<8}")
    print("-" * 80)
    
    results = []
    for name, y_prob in val_probas.items():
        t, _ = find_best_threshold(y_true, y_prob)
        y_pred = (y_prob >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        results.append({
            "Model": name, "F1": f1_score(y_true, y_pred, zero_division=0),
            "AUC": roc_auc_score(y_true, y_prob), "Recall": recall_score(y_true, y_pred, zero_division=0),
            "FNR": fn / (fn + tp)
        })
    
    results = sorted(results, key=lambda x: x["F1"], reverse=True)
    for i, r in enumerate(results, 1):
        print(f"{i:<4} {r['Model']:<20} {r['F1']:.4f}     {r['AUC']:.4f}     {r['Recall']:.4f}     {r['FNR']:.4f}")
    print("=" * 80)
    return results


# ════════════════════════════════════════════════════════════
# ██ 메인 실행 파트 ██
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    start_time = time.time()
    print("=" * 60)
    print("📂 데이터 준비 중...")
    
    df_csic = pd.concat([
        parse_csic_file(BASE_DIR / "cisc_normalTraffic_train.txt"),
        parse_csic_file(BASE_DIR / "cisc_normalTraffic_test.txt"),
        parse_csic_file(BASE_DIR / "cisc_anomalousTraffic_test.txt"),
    ], ignore_index=True)
    df_csic_train, df_csic_temp = train_test_split(df_csic, test_size=0.30, random_state=RANDOM_STATE, stratify=df_csic["class"])
    df_csic_val,   df_csic_test = train_test_split(df_csic_temp, test_size=2/3, random_state=RANDOM_STATE, stratify=df_csic_temp["class"])
    
    df_capec = parse_capec_file(BASE_DIR / "data_capec_multilabel.csv")
    df_capec_train, df_capec_temp = train_test_split(df_capec, test_size=0.30, random_state=RANDOM_STATE, stratify=df_capec["class"])
    df_capec_val,   df_capec_test = train_test_split(df_capec_temp, test_size=2/3, random_state=RANDOM_STATE, stratify=df_capec_temp["class"])
    
    df_for_enc = pd.concat([df_csic_train, df_capec_train], ignore_index=True)
    encoders   = {col: fit_encoder(df_for_enc[col]) for col in CATEGORICAL_COLUMNS}
    
    df_csic_train_enc  = apply_encoders(df_csic_train, encoders)
    df_csic_val_enc    = apply_encoders(df_csic_val,   encoders)
    df_csic_test_enc   = apply_encoders(df_csic_test,  encoders)
    df_capec_train_enc = apply_encoders(df_capec_train, encoders)
    df_capec_val_enc   = apply_encoders(df_capec_val,   encoders)
    df_capec_test_enc  = apply_encoders(df_capec_test,  encoders)
    
    print("📈 SMOTE-ENN 증강 중 (CSIC train)...")
    X_csic_tr = df_csic_train_enc[FEATURES]
    y_csic_tr = df_csic_train_enc["class"]
    smote_enn = SMOTEENN(sampling_strategy=1.0, random_state=RANDOM_STATE)
    X_csic_aug, y_csic_aug = smote_enn.fit_resample(X_csic_tr, y_csic_tr)
    X_csic_aug = pd.DataFrame(X_csic_aug, columns=FEATURES)
    y_csic_aug = pd.Series(y_csic_aug)
    
    X_train = pd.concat([X_csic_aug,                    df_capec_train_enc[FEATURES]], ignore_index=True)
    y_train = pd.concat([y_csic_aug,                    df_capec_train_enc["class"]],  ignore_index=True)
    X_val   = pd.concat([df_csic_val_enc[FEATURES],     df_capec_val_enc[FEATURES]],   ignore_index=True)
    y_val   = pd.concat([df_csic_val_enc["class"],       df_capec_val_enc["class"]],    ignore_index=True)
    X_test  = pd.concat([df_csic_test_enc[FEATURES],    df_capec_test_enc[FEATURES]],  ignore_index=True)
    y_test  = pd.concat([df_csic_test_enc["class"],      df_capec_test_enc["class"]],   ignore_index=True)
    
    print(f"   Train: {len(X_train):,}건  Val: {len(X_val):,}건  Test: {len(X_test):,}건")
    print("✅ 데이터 준비 완료\n")
    
    trained_models = {}
    val_probas     = {}
    
    # 모델 튜닝 실행
    m = tune_random_forest(X_train, y_train, X_val, y_val)
    trained_models["RandomForest"] = m; val_probas["RandomForest"] = m.predict_proba(X_val)[:,1]
    
    m = tune_extra_trees(X_train, y_train, X_val, y_val)
    trained_models["ExtraTrees"] = m; val_probas["ExtraTrees"] = m.predict_proba(X_val)[:,1]
    
    m = tune_xgboost(X_train, y_train, X_val, y_val)
    trained_models["XGBoost"] = m; val_probas["XGBoost"] = m.predict_proba(X_val)[:,1]
    """
    m = tune_gradient_boosting(X_train, y_train, X_val, y_val)
    trained_models["GradientBoosting"] = m; val_probas["GradientBoosting"] = m.predict_proba(X_val)[:,1]
    """
    # 기존 GradientBoosting 코드를 아래 2줄로 교체
    m = tune_hist_gradient_boosting(X_train, y_train, X_val, y_val)
    trained_models["HistGradientBoosting"] = m; val_probas["HistGradientBoosting"] = m.predict_proba(X_val)[:,1]

    print("\n\n📊 4대장 후보 모델 Val 성능 비교")
    perf_results = print_table(val_probas, y_val)
    
    print("\n\n⚖️  scipy로 최적 앙상블 가중치 탐색 중...")
    opt_weights = optimize_weights(val_probas, y_val)
    for name, w in sorted(opt_weights.items(), key=lambda x: -x[1]):
        print(f"   {name:<20} {w:.4f}  " + "█" * int(w * 50))
    
    print("\n\n🏁 극한 튜닝 완료! Test 최종 성능 측정 중...")
    test_probas   = {n: m.predict_proba(X_test)[:,1] for n, m in trained_models.items()}
    combined_val  = sum(opt_weights[n] * val_probas[n]  for n in opt_weights)
    combined_test = sum(opt_weights[n] * test_probas[n] for n in opt_weights)
    
    best_t, _ = find_best_threshold(y_val, combined_val)
    y_pred_test = (combined_test >= best_t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred_test).ravel()
    
    print(f"\n   Threshold : {best_t:.2f}")
    print(f"   Accuracy  : {accuracy_score(y_test, y_pred_test):.4f}")
    print(f"   F1-Score  : {f1_score(y_test, y_pred_test, zero_division=0):.4f}")
    print(f"   Recall    : {recall_score(y_test, y_pred_test, zero_division=0):.4f}")
    print(f"   AUC-ROC   : {roc_auc_score(y_test, combined_test):.4f}")
    print(f"   FNR(미탐률) : {fn/(fn+tp):.4f}")
    
    elapsed = (time.time() - start_time) / 3600
    print(f"\n⏳ 총 소요 시간: {elapsed:.2f} 시간")
    
    joblib.dump({
        "models": trained_models, "val_probas": val_probas,
        "optimized_weights": opt_weights, "threshold": best_t,
        "encoders": encoders, "features": FEATURES,
        "performance": perf_results, "model_type": "extreme_weighted_ensemble",
    }, BUNDLE_EXT)
    
    print(f"✅  번들 저장 완료: {BUNDLE_EXT}")