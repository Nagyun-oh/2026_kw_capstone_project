"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
model_selection.py — 보안 로그 탐지 모델 선별 및 최적 앙상블 구성
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[비교 모델 — 보안 로그 탐지 논문 기반 선별]

  ■ 기존 앙상블 (재튜닝)
    ① LightGBM      — 빠른 학습속도, NIDS 논문에서 최상위 성능
    ② RandomForest   — NIDS 전통적 기준 모델, 안정성 높음
    ③ ExtraTrees     — RF 보다 무작위성 강해 과적합 방지

  ■ 신규 후보
    ④ XGBoost        — CICIDS/NSL-KDD 등 대부분 NIDS 논문의 기준 모델
    ⑤ CatBoost       — 범주형 피처(method, user_agent 등) 특화, 최근 보안 논문 채택 증가
    ⑥ GradientBoosting — 전통적 부스팅, 해석 가능성 높아 보안 도메인 신뢰도 높음

  ※ GRU/MLP 제외 이유:
    테이블 형식 보안 로그에서 트리 계열이 일관되게 우수한 성능을 보임
    (Ref: "Comparative Study of ML for Network Intrusion Detection", IEEE 2023)

[실행 방법]
  pip install optuna xgboost catboost
  python model_selection.py

[출력 결과]
  - 6개 모델 Val 성능 비교표 (F1 / AUC-ROC / Recall / FNR)
  - scipy 최적 앙상블 가중치
  - model_bundle_v2.pkl 저장

[예상 실행 시간]
  N_TRIALS=30 기준: 약 2~4시간 (CPU)
  빠른 테스트: N_TRIALS=10 으로 줄이면 30분~1시간
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import warnings
warnings.filterwarnings("ignore")

from pathlib import Path
from urllib.parse import unquote, urlparse
import re

import joblib
import numpy as np
import pandas as pd
import optuna
optuna.logging.set_verbosity(optuna.logging.WARNING)

from imblearn.combine import SMOTEENN
from sklearn.ensemble import (
    ExtraTreesClassifier, RandomForestClassifier,
    GradientBoostingClassifier
)
from sklearn.metrics import (
    f1_score, roc_auc_score, accuracy_score,
    recall_score, confusion_matrix
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from scipy.optimize import minimize
import lightgbm as lgb

# XGBoost
try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("⚠️  XGBoost 미설치 → 제외  (pip install xgboost)")

# CatBoost
try:
    from catboost import CatBoostClassifier
    HAS_CATBOOST = True
except ImportError:
    HAS_CATBOOST = False
    print("⚠️  CatBoost 미설치 → 제외  (pip install catboost)")


# ════════════════════════════════════════════════════════════
# 0. 설정값
# ════════════════════════════════════════════════════════════

N_TRIALS     = 30      # Optuna 탐색 횟수 (줄이면 빠름)
OPTUNA_RATIO = 0.2     # Optuna 튜닝 시 Train 사용 비율 (속도 최적화)
RANDOM_STATE = 42
BASE_DIR     = Path(__file__).resolve().parent
BUNDLE_V2    = BASE_DIR / "model_bundle_v2.pkl"


# ════════════════════════════════════════════════════════════
# 1. 공통 상수 (main.py 와 동일)
# ════════════════════════════════════════════════════════════

ATTACK_KEYWORDS         = ["select","insert","update","delete","drop","union","exec","script","alert","../"]
SQL_KEYWORDS            = ["select","insert","update","delete","drop","union","where","from","exec","sleep","benchmark"]
XSS_KEYWORDS            = ["<script","script","alert","onerror","onload","javascript:","<img","<svg"]
PATH_TRAVERSAL_PATTERNS = ["../","..\\","%2e%2e","etc/passwd","boot.ini"]
SPECIAL_CHARS           = ["'",'"',"<",">","--",";","%","(",")",  "="]
CATEGORICAL_COLUMNS     = ["method","user_agent","url_path","file_extension"]
FEATURES = [
    "method_encoded","user_agent_encoded","url_path_encoded","file_extension_encoded",
    "url_len","query_len","body_len","total_len","path_depth","param_count",
    "special_char_count","special_char_ratio","encoded_char_count","digit_ratio","alpha_ratio",
    "has_keywords_query","has_keywords_body",
    "sql_keyword_count","xss_keyword_count","path_traversal_count",
    "has_script_tag","has_union_select","has_comment_pattern",
]


# ════════════════════════════════════════════════════════════
# 2. 헬퍼 / 피처 추출 (train_and_save_model.py 와 동일)
# ════════════════════════════════════════════════════════════

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
    visible_url  = full_url if full_url is not None else (
        url_path + (f"?{query_params}" if query_params else "")
    )
    decoded_q   = unquote(query_params)
    decoded_b   = unquote(body_content)
    combined    = f"{unquote(visible_url)} {decoded_b}"
    total_len   = len(visible_url) + len(body_content)
    scc = sum(visible_url.count(c) + body_content.count(c) for c in SPECIAL_CHARS)
    return {
        "method": method, "user_agent": user_agent, "url_path": url_path,
        "file_extension": (Path(url_path).suffix.lower().lstrip(".") or "NONE"),
        "url_len": len(visible_url), "query_len": len(query_params),
        "body_len": len(body_content), "total_len": total_len,
        "path_depth": len([p for p in url_path.split("/") if p]),
        "param_count": query_params.count("=") + body_content.count("="),
        "special_char_count": scc,
        "special_char_ratio": safe_ratio(scc, total_len),
        "encoded_char_count": visible_url.count("%") + body_content.count("%"),
        "digit_ratio": safe_ratio(sum(c.isdigit() for c in visible_url + body_content), total_len),
        "alpha_ratio": safe_ratio(sum(c.isalpha() for c in visible_url + body_content), total_len),
        "has_keywords_query":   has_any(decoded_q, ATTACK_KEYWORDS),
        "has_keywords_body":    has_any(decoded_b, ATTACK_KEYWORDS),
        "sql_keyword_count":    count_matches(combined, SQL_KEYWORDS),
        "xss_keyword_count":    count_matches(combined, XSS_KEYWORDS),
        "path_traversal_count": count_matches(combined, PATH_TRAVERSAL_PATTERNS),
        "has_script_tag":       int("<script" in combined.lower()),
        "has_union_select":     int("union" in combined.lower() and "select" in combined.lower()),
        "has_comment_pattern":  int("--" in combined or "/*" in combined or "*/" in combined),
    }

def parse_csic_file(file_path):
    with file_path.open("r", encoding="utf-8") as f:
        content = f.read()
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
        if s > best_f1:
            best_f1, best_t = s, float(round(t, 2))
    return best_t, best_f1


# ════════════════════════════════════════════════════════════
# 3. Optuna 튜닝 함수 — 각 모델별
# ════════════════════════════════════════════════════════════

def _sub_split(X_train, y_train):
    """Optuna 속도 최적화용 서브셋 분리"""
    X_sub, _, y_sub, _ = train_test_split(
        X_train, y_train, train_size=OPTUNA_RATIO,
        random_state=RANDOM_STATE, stratify=y_train
    )
    return X_sub, y_sub


def tune_lightgbm(X_train, y_train, X_val, y_val):
    print(f"  [1/6] LightGBM  Optuna {N_TRIALS} trials...")
    X_sub, y_sub = _sub_split(X_train, y_train)

    def objective(trial):
        m = lgb.LGBMClassifier(
            n_estimators      = trial.suggest_int("n_estimators", 100, 500),
            learning_rate     = trial.suggest_float("lr", 0.01, 0.15, log=True),
            max_depth         = trial.suggest_int("max_depth", 3, 12),
            num_leaves        = trial.suggest_int("num_leaves", 20, 150),
            min_child_samples = trial.suggest_int("min_child_samples", 10, 60),
            subsample         = trial.suggest_float("subsample", 0.6, 1.0),
            colsample_bytree  = trial.suggest_float("colsample_bytree", 0.6, 1.0),
            random_state=RANDOM_STATE, verbose=-1,
        )
        m.fit(X_sub, y_sub)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=False)
    p = study.best_params
    model = lgb.LGBMClassifier(
        n_estimators=p["n_estimators"], learning_rate=p["lr"],
        max_depth=p["max_depth"], num_leaves=p["num_leaves"],
        min_child_samples=p["min_child_samples"], subsample=p["subsample"],
        colsample_bytree=p["colsample_bytree"],
        random_state=RANDOM_STATE, verbose=-1,
    )
    model.fit(X_train, y_train)
    print(f"     Best Val F1: {study.best_value:.4f}  |  params: {p}")
    return model


def tune_random_forest(X_train, y_train, X_val, y_val):
    print(f"  [2/6] RandomForest  Optuna {N_TRIALS} trials...")
    X_sub, y_sub = _sub_split(X_train, y_train)

    def objective(trial):
        m = RandomForestClassifier(
            n_estimators     = trial.suggest_int("n_estimators", 100, 400),
            max_depth        = trial.suggest_int("max_depth", 5, 30),
            min_samples_split= trial.suggest_int("min_samples_split", 2, 10),
            min_samples_leaf = trial.suggest_int("min_samples_leaf", 1, 5),
            class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
        )
        m.fit(X_sub, y_sub)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=False)
    p = study.best_params
    model = RandomForestClassifier(
        n_estimators=p["n_estimators"], max_depth=p["max_depth"],
        min_samples_split=p["min_samples_split"], min_samples_leaf=p["min_samples_leaf"],
        class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print(f"     Best Val F1: {study.best_value:.4f}  |  params: {p}")
    return model


def tune_extra_trees(X_train, y_train, X_val, y_val):
    print(f"  [3/6] ExtraTrees  Optuna {N_TRIALS} trials...")
    X_sub, y_sub = _sub_split(X_train, y_train)

    def objective(trial):
        m = ExtraTreesClassifier(
            n_estimators     = trial.suggest_int("n_estimators", 100, 400),
            max_depth        = trial.suggest_int("max_depth", 5, 30),
            min_samples_split= trial.suggest_int("min_samples_split", 2, 10),
            class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
        )
        m.fit(X_sub, y_sub)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=False)
    p = study.best_params
    model = ExtraTreesClassifier(
        n_estimators=p["n_estimators"], max_depth=p["max_depth"],
        min_samples_split=p["min_samples_split"],
        class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print(f"     Best Val F1: {study.best_value:.4f}  |  params: {p}")
    return model


def tune_xgboost(X_train, y_train, X_val, y_val):
    print(f"  [4/6] XGBoost  Optuna {N_TRIALS} trials...")
    X_sub, y_sub = _sub_split(X_train, y_train)
    # 불균형 보정
    spw = float((y_sub == 0).sum()) / max(float((y_sub == 1).sum()), 1)

    def objective(trial):
        m = XGBClassifier(
            n_estimators      = trial.suggest_int("n_estimators", 100, 500),
            learning_rate     = trial.suggest_float("lr", 0.01, 0.15, log=True),
            max_depth         = trial.suggest_int("max_depth", 3, 10),
            subsample         = trial.suggest_float("subsample", 0.6, 1.0),
            colsample_bytree  = trial.suggest_float("colsample_bytree", 0.6, 1.0),
            min_child_weight  = trial.suggest_int("min_child_weight", 1, 10),
            scale_pos_weight=spw, random_state=RANDOM_STATE,
            verbosity=0, eval_metric="logloss",
        )
        m.fit(X_sub, y_sub)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=False)
    p = study.best_params
    model = XGBClassifier(
        n_estimators=p["n_estimators"], learning_rate=p["lr"],
        max_depth=p["max_depth"], subsample=p["subsample"],
        colsample_bytree=p["colsample_bytree"], min_child_weight=p["min_child_weight"],
        scale_pos_weight=spw, random_state=RANDOM_STATE,
        verbosity=0, eval_metric="logloss",
    )
    model.fit(X_train, y_train)
    print(f"     Best Val F1: {study.best_value:.4f}  |  params: {p}")
    return model


def tune_catboost(X_train, y_train, X_val, y_val):
    print(f"  [5/6] CatBoost  Optuna {N_TRIALS} trials...")
    X_sub, y_sub = _sub_split(X_train, y_train)

    def objective(trial):
        m = CatBoostClassifier(
            iterations    = trial.suggest_int("iterations", 100, 500),
            learning_rate = trial.suggest_float("lr", 0.01, 0.15, log=True),
            depth         = trial.suggest_int("depth", 4, 10),
            l2_leaf_reg   = trial.suggest_float("l2_leaf_reg", 1.0, 10.0),
            random_seed=RANDOM_STATE, verbose=0,
            # 범주형 피처 인덱스 자동 지정
            auto_class_weights="Balanced",
        )
        m.fit(X_sub, y_sub)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=False)
    p = study.best_params
    model = CatBoostClassifier(
        iterations=p["iterations"], learning_rate=p["lr"],
        depth=p["depth"], l2_leaf_reg=p["l2_leaf_reg"],
        random_seed=RANDOM_STATE, verbose=0,
        auto_class_weights="Balanced",
    )
    model.fit(X_train, y_train)
    print(f"     Best Val F1: {study.best_value:.4f}  |  params: {p}")
    return model


def tune_gradient_boosting(X_train, y_train, X_val, y_val):
    print(f"  [6/6] GradientBoosting  Optuna {N_TRIALS} trials...")
    # GBM은 느려서 서브셋을 더 작게 사용
    X_sub, _, y_sub, _ = train_test_split(
        X_train, y_train, train_size=min(OPTUNA_RATIO, 0.1),
        random_state=RANDOM_STATE, stratify=y_train
    )

    def objective(trial):
        m = GradientBoostingClassifier(
            n_estimators  = trial.suggest_int("n_estimators", 100, 300),
            learning_rate = trial.suggest_float("lr", 0.01, 0.15, log=True),
            max_depth     = trial.suggest_int("max_depth", 3, 8),
            subsample     = trial.suggest_float("subsample", 0.6, 1.0),
            random_state=RANDOM_STATE,
        )
        m.fit(X_sub, y_sub)
        return f1_score(y_val, (m.predict_proba(X_val)[:,1] >= 0.5).astype(int), zero_division=0)

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=False)
    p = study.best_params
    model = GradientBoostingClassifier(
        n_estimators=p["n_estimators"], learning_rate=p["lr"],
        max_depth=p["max_depth"], subsample=p["subsample"],
        random_state=RANDOM_STATE,
    )
    model.fit(X_train, y_train)
    print(f"     Best Val F1: {study.best_value:.4f}  |  params: {p}")
    return model


# ════════════════════════════════════════════════════════════
# 4. 최적 앙상블 가중치 탐색 (scipy Nelder-Mead)
# ════════════════════════════════════════════════════════════

def optimize_weights(proba_dict: dict, y_val: pd.Series) -> dict:
    """
    각 모델의 Val 예측 확률을 받아서
    F1-Score를 최대화하는 가중치 조합을 scipy로 탐색한다.
    """
    names  = list(proba_dict.keys())
    probas = [proba_dict[n] for n in names]

    def objective(weights):
        w = np.abs(weights)
        w = w / w.sum()
        combined = sum(wi * pi for wi, pi in zip(w, probas))
        best_f1 = max(
            f1_score(y_val, (combined >= t).astype(int), zero_division=0)
            for t in np.arange(0.3, 0.8, 0.05)
        )
        return -best_f1

    result = minimize(
        objective, np.ones(len(names)) / len(names),
        method="Nelder-Mead",
        options={"maxiter": 5000, "xatol": 1e-6, "fatol": 1e-6}
    )
    w = np.abs(result.x)
    w = w / w.sum()
    return {name: round(float(wi), 4) for name, wi in zip(names, w)}


# ════════════════════════════════════════════════════════════
# 5. 성능 평가 및 결과 출력
# ════════════════════════════════════════════════════════════

def evaluate(name, y_true, y_prob):
    t, _ = find_best_threshold(y_true, y_prob)
    y_pred = (y_prob >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "Model":     name,
        "Val F1":    round(f1_score(y_true, y_pred, zero_division=0), 4),
        "AUC-ROC":   round(roc_auc_score(y_true, y_prob), 4),
        "Recall":    round(recall_score(y_true, y_pred, zero_division=0), 4),
        "Accuracy":  round(accuracy_score(y_true, y_pred), 4),
        "FNR":       round(fn / (fn + tp), 4),
        "Threshold": t,
    }

def print_table(results):
    results = sorted(results, key=lambda x: x["Val F1"], reverse=True)
    existing = {"LightGBM", "RandomForest", "ExtraTrees"}
    print("\n" + "=" * 90)
    print(f"{'순위':<4} {'모델':<20} {'Val F1':<10} {'AUC-ROC':<10} {'Recall':<10} {'FNR':<8} {'비고'}")
    print("-" * 90)
    for i, r in enumerate(results, 1):
        tag = "기존" if r["Model"] in existing else "★신규"
        print(f"{i:<4} {r['Model']:<20} {r['Val F1']:<10} {r['AUC-ROC']:<10} "
              f"{r['Recall']:<10} {r['FNR']:<8} [{tag}]")
    print("=" * 90)
    return results


# ════════════════════════════════════════════════════════════
# ██ 메인 실행 ██
# ════════════════════════════════════════════════════════════

print("=" * 60)
print("📂 데이터 준비 중...")

# CSIC 로딩 및 7:1:2 분리
df_csic = pd.concat([
    parse_csic_file(BASE_DIR / "cisc_normalTraffic_train.txt"),
    parse_csic_file(BASE_DIR / "cisc_normalTraffic_test.txt"),
    parse_csic_file(BASE_DIR / "cisc_anomalousTraffic_test.txt"),
], ignore_index=True)
df_csic_train, df_csic_temp = train_test_split(df_csic, test_size=0.30, random_state=RANDOM_STATE, stratify=df_csic["class"])
df_csic_val,   df_csic_test = train_test_split(df_csic_temp, test_size=2/3, random_state=RANDOM_STATE, stratify=df_csic_temp["class"])

# CAPEC 로딩 및 7:1:2 분리
df_capec = parse_capec_file(BASE_DIR / "data_capec_multilabel.csv")
df_capec_train, df_capec_temp = train_test_split(df_capec, test_size=0.30, random_state=RANDOM_STATE, stratify=df_capec["class"])
df_capec_val,   df_capec_test = train_test_split(df_capec_temp, test_size=2/3, random_state=RANDOM_STATE, stratify=df_capec_temp["class"])

# LabelEncoder 학습 + 인코딩
df_for_enc = pd.concat([df_csic_train, df_capec_train], ignore_index=True)
encoders   = {col: fit_encoder(df_for_enc[col]) for col in CATEGORICAL_COLUMNS}

df_csic_train_enc  = apply_encoders(df_csic_train,  encoders)
df_csic_val_enc    = apply_encoders(df_csic_val,    encoders)
df_csic_test_enc   = apply_encoders(df_csic_test,   encoders)
df_capec_train_enc = apply_encoders(df_capec_train, encoders)
df_capec_val_enc   = apply_encoders(df_capec_val,   encoders)
df_capec_test_enc  = apply_encoders(df_capec_test,  encoders)

# SMOTE-ENN 증강 (CSIC train 만)
print("📈 SMOTE-ENN 증강 중 (CSIC train)...")
X_csic_tr = df_csic_train_enc[FEATURES]
y_csic_tr = df_csic_train_enc["class"]
smote_enn = SMOTEENN(sampling_strategy=1.0, random_state=RANDOM_STATE)
X_csic_aug, y_csic_aug = smote_enn.fit_resample(X_csic_tr, y_csic_tr)
X_csic_aug = pd.DataFrame(X_csic_aug, columns=FEATURES)
y_csic_aug = pd.Series(y_csic_aug)

# 최종 Train / Val / Test 조립
X_train = pd.concat([X_csic_aug,                    df_capec_train_enc[FEATURES]], ignore_index=True)
y_train = pd.concat([y_csic_aug,                    df_capec_train_enc["class"]],  ignore_index=True)
X_val   = pd.concat([df_csic_val_enc[FEATURES],     df_capec_val_enc[FEATURES]],   ignore_index=True)
y_val   = pd.concat([df_csic_val_enc["class"],       df_capec_val_enc["class"]],    ignore_index=True)
X_test  = pd.concat([df_csic_test_enc[FEATURES],    df_capec_test_enc[FEATURES]],  ignore_index=True)
y_test  = pd.concat([df_csic_test_enc["class"],      df_capec_test_enc["class"]],   ignore_index=True)

print(f"   Train: {len(X_train):,}건  Val: {len(X_val):,}건  Test: {len(X_test):,}건")
print("✅ 데이터 준비 완료\n")


# ── Optuna 튜닝 ──────────────────────────────────────────
print(f"🤖 후보 모델 Optuna 튜닝 시작 (N_TRIALS={N_TRIALS})\n")

trained_models = {}
val_probas     = {}

# 기존 3개
m = tune_lightgbm(X_train, y_train, X_val, y_val)
trained_models["LightGBM"]    = m;  val_probas["LightGBM"]    = m.predict_proba(X_val)[:,1]

m = tune_random_forest(X_train, y_train, X_val, y_val)
trained_models["RandomForest"] = m; val_probas["RandomForest"] = m.predict_proba(X_val)[:,1]

m = tune_extra_trees(X_train, y_train, X_val, y_val)
trained_models["ExtraTrees"]  = m;  val_probas["ExtraTrees"]  = m.predict_proba(X_val)[:,1]

# 신규 3개
if HAS_XGBOOST:
    m = tune_xgboost(X_train, y_train, X_val, y_val)
    trained_models["XGBoost"]  = m; val_probas["XGBoost"]  = m.predict_proba(X_val)[:,1]

if HAS_CATBOOST:
    m = tune_catboost(X_train, y_train, X_val, y_val)
    trained_models["CatBoost"] = m; val_probas["CatBoost"] = m.predict_proba(X_val)[:,1]

m = tune_gradient_boosting(X_train, y_train, X_val, y_val)
trained_models["GradientBoosting"] = m; val_probas["GradientBoosting"] = m.predict_proba(X_val)[:,1]


# ── 성능 비교표 출력 ────────────────────────────────────
print("\n\n📊 후보 모델 Val 성능 비교")
results = [evaluate(n, y_val, p) for n, p in val_probas.items()]
sorted_results = print_table(results)

print("\n💡 판단 기준:")
print("   Val F1  ≥ 0.93  →  앙상블 포함 권장")
print("   Val F1  < 0.90  →  기존 대비 개선 없음, 제외 권장")
print("   FNR 낮을수록     →  보안 관점 탐지율 높음 (중요)")


# ── 최적 가중치 탐색 ─────────────────────────────────────
print("\n\n⚖️  scipy로 최적 앙상블 가중치 탐색 중...")
opt_weights = optimize_weights(val_probas, y_val)

print("\n   최적 가중치:")
for name, w in sorted(opt_weights.items(), key=lambda x: -x[1]):
    bar = "█" * int(w * 50)
    print(f"   {name:<22} {w:.4f}  {bar}")


# ── 최적 가중치 적용 → Test 성능 ────────────────────────
print("\n\n🏁 최적 가중치 적용 → Test 최종 성능")
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
print(f"   FPR       : {fp/(fp+tn):.4f}")
print(f"   FNR       : {fn/(fn+tp):.4f}")
print(f"   Confusion : TN={tn:,}  FP={fp:,}  FN={fn:,}  TP={tp:,}")


# ── 번들 저장 ────────────────────────────────────────────
joblib.dump({
    "models":            trained_models,
    "val_probas":        val_probas,
    "optimized_weights": opt_weights,
    "threshold":         best_t,
    "encoders":          encoders,
    "features":          FEATURES,
    "performance":       sorted_results,
    "model_type":        "custom_weighted_ensemble_v2",
    "feature_version":   "ensemble_v5_security_models",
}, BUNDLE_V2)

print(f"\n✅ 번들 저장 완료: {BUNDLE_V2}")
print("=" * 60)
print("\n📌 다음 단계:")
print("   1. 위 성능 비교표 보고 포함/제외 모델 결정")
print("   2. 최종 선택 모델 조합으로 train_and_save_model.py 수정")
print("   3. train_and_save_model.py 재실행 → main.py 서버 재시작")