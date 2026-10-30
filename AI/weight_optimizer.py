"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ultimate_weight_optimizer.py — Optuna 기반 앙상블 가중치 10,000회 전수조사
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import warnings
warnings.filterwarnings("ignore")

import joblib
import numpy as np
import pandas as pd
import optuna
from pathlib import Path
from urllib.parse import unquote, urlparse
import re
import time

from sklearn.metrics import f1_score, accuracy_score, recall_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import train_test_split

# 1만 번의 로그가 화면을 덮는 것을 방지하기 위해 에러만 표시
optuna.logging.set_verbosity(optuna.logging.ERROR)

# ════════════════════════════════════════════════════════════
# 0. 설정값
# ════════════════════════════════════════════════════════════
N_TRIALS     = 10000   # 1만 번 전수조사 (단 몇 분이면 끝납니다)
RANDOM_STATE = 42
BASE_DIR     = Path(__file__).resolve().parent
BUNDLE_EXT   = BASE_DIR / "model_bundle_extreme.pkl"
BUNDLE_ULT   = BASE_DIR / "model_bundle_ultimate.pkl"

# ════════════════════════════════════════════════════════════
# 1. 헬퍼 함수 (데이터 로딩용)
# ════════════════════════════════════════════════════════════
ATTACK_KEYWORDS         = ["select","insert","update","delete","drop","union","exec","script","alert","../"]
SQL_KEYWORDS            = ["select","insert","update","delete","drop","union","where","from","exec","sleep","benchmark"]
XSS_KEYWORDS            = ["<script","script","alert","onerror","onload","javascript:","<img","<svg"]
PATH_TRAVERSAL_PATTERNS = ["../","..\\","%2e%2e","etc/passwd","boot.ini"]
SPECIAL_CHARS           = ["'",'"',"<",">","--",";","%","(",")",  "="]
#CATEGORICAL_COLUMNS     = ["method","user_agent","url_path","file_extension"]
CATEGORICAL_COLUMNS     = ["method","user_agent"]
FEATURES = [
    "method_encoded","user_agent_encoded",
    #"url_path_encoded","file_extension_encoded",    "url_len","query_len",
    "body_len",
    #"total_len","path_depth","param_count",
    "special_char_count","special_char_ratio",
    #"encoded_char_count",
    "digit_ratio","alpha_ratio",
    #"has_keywords_query",
    "has_keywords_body",
    "sql_keyword_count","xss_keyword_count","path_traversal_count",
    "has_script_tag","has_union_select","has_comment_pattern",
]

def count_matches(text, patterns): return sum((text or "").lower().count(p.lower()) for p in patterns)
def has_any(text, patterns): return int(count_matches(text, patterns) > 0)
def safe_ratio(part, total): return part / total if total else 0.0

def normalize_full_url(raw):
    if not raw: return "", ""
    parsed = urlparse(raw)
    return parsed.path or raw.split("?")[0], parsed.query or (raw.split("?",1)[1] if "?" in raw else "")

def build_feature_row(method, url_path, query_params, body_content, user_agent, full_url=None):
    method       = (method or "UNKNOWN").upper()
    url_path     = url_path or ""
    query_params = query_params or ""
    body_content = "" if body_content in (None, "null") else body_content
    user_agent   = user_agent or ""
    visible_url  = full_url if full_url is not None else (url_path + (f"?{query_params}" if query_params else ""))
    decoded_q    = unquote(query_params)
    decoded_b    = unquote(body_content)
    combined     = f"{unquote(visible_url)} {decoded_b}"
    total_len    = len(visible_url) + len(body_content)
    scc = sum(visible_url.count(c) + body_content.count(c) for c in SPECIAL_CHARS)
    return {
        "method": method, "user_agent": user_agent, "url_path": url_path,
        "file_extension": (Path(url_path).suffix.lower().lstrip(".") or "NONE"),
        "url_len": len(visible_url), "query_len": len(query_params),
        "body_len": len(body_content), "total_len": total_len,
        "path_depth": len([p for p in url_path.split("/") if p]),
        "param_count": query_params.count("=") + body_content.count("="),
        "special_char_count": scc, "special_char_ratio": safe_ratio(scc, total_len),
        "encoded_char_count": visible_url.count("%") + body_content.count("%"),
        "digit_ratio": safe_ratio(sum(c.isdigit() for c in visible_url + body_content), total_len),
        "alpha_ratio": safe_ratio(sum(c.isalpha() for c in visible_url + body_content), total_len),
        "has_keywords_query": has_any(decoded_q, ATTACK_KEYWORDS),
        "has_keywords_body":  has_any(decoded_b, ATTACK_KEYWORDS),
        "sql_keyword_count":  count_matches(combined, SQL_KEYWORDS),
        "xss_keyword_count":  count_matches(combined, XSS_KEYWORDS),
        "path_traversal_count": count_matches(combined, PATH_TRAVERSAL_PATTERNS),
        "has_script_tag":     int("<script" in combined.lower()),
        "has_union_select":   int("union" in combined.lower() and "select" in combined.lower()),
        "has_comment_pattern":int("--" in combined or "/*" in combined or "*/" in combined),
    }

def parse_csic_file(file_path):
    with file_path.open("r", encoding="utf-8") as f: content = f.read()
    requests = re.findall(r"Start - Id:.*?\n(.*?)\nEnd - Id:", content, re.DOTALL)
    rows = []
    for req in requests:
        label = 1 if re.search(r"class: (Valid|Attack)", req) and re.search(r"class: (Valid|Attack)", req).group(1) == "Attack" else 0
        first_line = next((l for l in req.splitlines() if re.search(r"\b(GET|POST|PUT|DELETE)\b", l)), "")
        m = re.search(r"\b(GET|POST|PUT|DELETE)\b", first_line)
        method = m.group(1) if m else "UNKNOWN"
        um = re.search(r"http://[^\s]+", first_line)
        full_url = um.group(0) if um else ""
        url_path, query_params = normalize_full_url(full_url)
        ua = re.search(r"User-Agent: (.*)", req)
        body_content = req.split("\n\n", 1)[1].strip() if "\n\n" in req else ""
        row = build_feature_row(method, url_path, query_params, body_content if body_content!="null" else "", ua.group(1).strip() if ua else "", full_url)
        row["class"] = label
        rows.append(row)
    return pd.DataFrame(rows)

def parse_capec_file(file_path):
    df_raw = pd.read_csv(file_path, low_memory=False)
    rows = []
    for _, r in df_raw.iterrows():
        raw_req = str(r.get("request_http_request") or "")
        url_path, query_params = normalize_full_url(raw_req)
        row = build_feature_row(str(r.get("request_http_method") or "UNKNOWN").upper(), url_path, query_params, str(r.get("request_body") or ""), str(r.get("request_user_agent") or ""), raw_req)
        row["class"] = int((r.get("000 - Normal") == 0))
        rows.append(row)
    return pd.DataFrame(rows)

def apply_encoders(df, encoders):
    df = df.copy()
    for col, enc in encoders.items():
        known = set(enc.classes_)
        df[f"{col}_encoded"] = enc.transform(df[col].fillna("").astype(str).where(lambda s: s.isin(known), "UNKNOWN"))
    return df


# ════════════════════════════════════════════════════════════
# ██ 메인 실행 파트 ██
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    start_time = time.time()
    print("=" * 60)
    print("📂 1. 완성된 극한 모델 번들 로딩 중...")
    bundle = joblib.load(BUNDLE_EXT)
    models = bundle["models"]
    encoders = bundle["encoders"]
    
    print("📂 2. 평가용 Validation/Test 데이터 준비 중 (훈련 생략)...")
    df_csic = pd.concat([parse_csic_file(BASE_DIR / "cisc_normalTraffic_train.txt"), parse_csic_file(BASE_DIR / "cisc_normalTraffic_test.txt"), parse_csic_file(BASE_DIR / "cisc_anomalousTraffic_test.txt")], ignore_index=True)
    _, df_csic_temp = train_test_split(df_csic, test_size=0.30, random_state=RANDOM_STATE, stratify=df_csic["class"])
    df_csic_val, df_csic_test = train_test_split(df_csic_temp, test_size=2/3, random_state=RANDOM_STATE, stratify=df_csic_temp["class"])
    
    df_capec = parse_capec_file(BASE_DIR / "data_capec_multilabel.csv")
    _, df_capec_temp = train_test_split(df_capec, test_size=0.30, random_state=RANDOM_STATE, stratify=df_capec["class"])
    df_capec_val, df_capec_test = train_test_split(df_capec_temp, test_size=2/3, random_state=RANDOM_STATE, stratify=df_capec_temp["class"])
    
    df_csic_val_enc   = apply_encoders(df_csic_val, encoders)
    df_csic_test_enc  = apply_encoders(df_csic_test, encoders)
    df_capec_val_enc  = apply_encoders(df_capec_val, encoders)
    df_capec_test_enc = apply_encoders(df_capec_test, encoders)
    
    X_val  = pd.concat([df_csic_val_enc[FEATURES], df_capec_val_enc[FEATURES]], ignore_index=True)
    y_val  = pd.concat([df_csic_val_enc["class"], df_capec_val_enc["class"]], ignore_index=True)
    X_test = pd.concat([df_csic_test_enc[FEATURES], df_capec_test_enc[FEATURES]], ignore_index=True)
    y_test = pd.concat([df_csic_test_enc["class"], df_capec_test_enc["class"]], ignore_index=True)

    print("🤖 3. 각 모델별 예측 확률 계산 중 (단 몇 초 소요)...")
    val_probas = {name: m.predict_proba(X_val)[:, 1] for name, m in models.items()}
    test_probas = {name: m.predict_proba(X_test)[:, 1] for name, m in models.items()}

    print(f"\n⚖️  4. Optuna {N_TRIALS:,}회 글로벌 가중치 전수조사 시작!")
    def objective(trial):
        # 1. 가중치 4개 제안 (0.0 ~ 1.0)
        w_rf  = trial.suggest_float("w_RF", 0.0, 1.0)
        w_et  = trial.suggest_float("w_ET", 0.0, 1.0)
        w_xgb = trial.suggest_float("w_XGB", 0.0, 1.0)
        w_hgb = trial.suggest_float("w_HGB", 0.0, 1.0)
        
        # 2. 임계값(Threshold) 제안 (0.4 ~ 0.8 범위)
        threshold = trial.suggest_float("threshold", 0.4, 0.8)
        
        total_w = w_rf + w_et + w_xgb + w_hgb
        if total_w == 0: return 0.0
        
        w_rf, w_et, w_xgb, w_hgb = w_rf/total_w, w_et/total_w, w_xgb/total_w, w_hgb/total_w
        
        combined_prob = (
            w_rf * val_probas["RandomForest"] + 
            w_et * val_probas["ExtraTrees"] + 
            w_xgb * val_probas["XGBoost"] + 
            w_hgb * val_probas["HistGradientBoosting"]
        )
        
        y_pred = (combined_prob >= threshold).astype(int)
        return f1_score(y_val, y_pred, zero_division=0)

    # 진행률 콜백 함수
    def print_progress(study, trial):
        if trial.number % 1000 == 0 and trial.number > 0:
            print(f"   [진행 상황] {trial.number:,} / {N_TRIALS:,} 완료 ... (현재 최고 Val F1: {study.best_value:.5f})")

    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=N_TRIALS, callbacks=[print_progress])
    
    bp = study.best_params
    total = bp["w_RF"] + bp["w_ET"] + bp["w_XGB"] + bp["w_HGB"]
    best_weights = {
        "RandomForest": bp["w_RF"] / total,
        "ExtraTrees": bp["w_ET"] / total,
        "XGBoost": bp["w_XGB"] / total,
        "HistGradientBoosting": bp["w_HGB"] / total
    }
    best_t = bp["threshold"]
    
    print("\n" + "=" * 60)
    print("🏆 [Optuna 최종 글로벌 최적 가중치]")
    for name, w in sorted(best_weights.items(), key=lambda x: -x[1]):
        print(f"   {name:<22} {w:.4f}  " + "█" * int(w * 50))
    print(f"\n   최적 Threshold : {best_t:.4f}")
    
    print("\n🏁 Test 최종 성능 측정 중 (Ultimate Version)...")
    combined_test = sum(best_weights[n] * test_probas[n] for n in best_weights)
    y_pred_test = (combined_test >= best_t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred_test).ravel()
    
    print(f"   Accuracy   : {accuracy_score(y_test, y_pred_test):.5f}")
    print(f"   F1-Score   : {f1_score(y_test, y_pred_test, zero_division=0):.5f}")
    print(f"   Recall     : {recall_score(y_test, y_pred_test, zero_division=0):.5f}")
    print(f"   AUC-ROC    : {roc_auc_score(y_test, combined_test):.5f}")
    print(f"   FNR(미탐률)  : {fn/(fn+tp):.5f}")
    
    elapsed = time.time() - start_time
    print(f"\n⏳ 총 소요 시간: {elapsed:.2f} 초")
    
    bundle["optimized_weights"] = best_weights
    bundle["threshold"] = best_t
    bundle["model_type"] = "ultimate_global_weighted_ensemble"
    
    joblib.dump(bundle, BUNDLE_ULT)
    print(f"✅ 새로운 번들 저장 완료: {BUNDLE_ULT}")
    print("=" * 60)