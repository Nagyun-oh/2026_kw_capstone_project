"""
Train and save the web-attack detection ensemble model.

데이터셋:
  - CSIC 2010  : 학습 전용 (+ SMOTE & Gaussian Noise 증강)
  - CAPEC Multilabel : train 70% / val 10% / test 20% 으로 분리
                       공격/정상 비율은 stratify로 유지

학습(Train) : CSIC 전체 + 증강본  +  CAPEC train (70%)
검증(Val)   : CAPEC val   (10%)   ← threshold 최적화에 사용
테스트(Test): CAPEC test  (20%)   ← 최종 성능 측정
"""

from pathlib import Path
import re
from urllib.parse import unquote, urlparse

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from imblearn.combine import SMOTEENN
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


BASE_DIR    = Path(__file__).resolve().parent
BUNDLE_PATH = BASE_DIR / "model_bundle.pkl"

# ── 공격 패턴 키워드 ─────────────────────────────────────
ATTACK_KEYWORDS = [
    "select", "insert", "update", "delete", "drop",
    "union", "exec", "script", "alert", "../",
]
SQL_KEYWORDS = [
    "select", "insert", "update", "delete", "drop",
    "union", "where", "from", "exec", "sleep", "benchmark",
]
XSS_KEYWORDS = [
    "<script", "script", "alert", "onerror", "onload",
    "javascript:", "<img", "<svg",
]
PATH_TRAVERSAL_PATTERNS = ["../", "..\\", "%2e%2e", "etc/passwd", "boot.ini"]
SPECIAL_CHARS = ["'", '"', "<", ">", "--", ";", "%", "(", ")", "="]


# ══════════════════════════════════════════════════════════
# 헬퍼 함수
# ══════════════════════════════════════════════════════════
def count_matches(text: str, patterns: list[str]) -> int:
    text_lower = (text or "").lower()
    return sum(text_lower.count(p.lower()) for p in patterns)


def has_any(text: str, patterns: list[str]) -> int:
    return int(count_matches(text, patterns) > 0)


def safe_ratio(part: int, total: int) -> float:
    return part / total if total else 0.0


def normalize_full_url(raw_url: str) -> tuple[str, str]:
    if not raw_url:
        return "", ""
    parsed = urlparse(raw_url)
    path  = parsed.path or raw_url.split("?")[0]
    query = parsed.query if parsed.query else (
        raw_url.split("?", 1)[1] if "?" in raw_url else ""
    )
    return path, query


def build_feature_row(
    method: str,
    url_path: str,
    query_params: str,
    body_content: str,
    user_agent: str,
    full_url: str | None = None,
) -> dict[str, object]:
    method       = (method or "UNKNOWN").upper()
    url_path     = url_path or ""
    query_params = query_params or ""
    body_content = "" if body_content in (None, "null") else body_content
    user_agent   = user_agent or ""

    visible_url   = full_url if full_url is not None else (
        url_path + (f"?{query_params}" if query_params else "")
    )
    decoded_query = unquote(query_params)
    decoded_body  = unquote(body_content)
    decoded_url   = unquote(visible_url)
    combined      = f"{decoded_url} {decoded_body}"

    url_len            = len(visible_url)
    query_len          = len(query_params)
    body_len           = len(body_content)
    total_len          = url_len + body_len
    special_char_count = (
        sum(visible_url.count(c)    for c in SPECIAL_CHARS) +
        sum(body_content.count(c)   for c in SPECIAL_CHARS)
    )
    encoded_char_count = visible_url.count("%") + body_content.count("%")
    digit_count        = sum(ch.isdigit() for ch in visible_url + body_content)
    alpha_count        = sum(ch.isalpha() for ch in visible_url + body_content)
    param_count        = query_params.count("=") + body_content.count("=")
    path_depth         = len([p for p in url_path.split("/") if p])
    file_extension     = Path(url_path).suffix.lower().lstrip(".") or "NONE"

    return {
        "method":               method,
        "user_agent":           user_agent,
        "url_path":             url_path,
        "file_extension":       file_extension,
        "url_len":              url_len,
        "query_len":            query_len,
        "body_len":             body_len,
        "total_len":            total_len,
        "path_depth":           path_depth,
        "param_count":          param_count,
        "special_char_count":   special_char_count,
        "special_char_ratio":   safe_ratio(special_char_count, total_len),
        "encoded_char_count":   encoded_char_count,
        "digit_ratio":          safe_ratio(digit_count, total_len),
        "alpha_ratio":          safe_ratio(alpha_count, total_len),
        "has_keywords_query":   has_any(decoded_query, ATTACK_KEYWORDS),
        "has_keywords_body":    has_any(decoded_body,  ATTACK_KEYWORDS),
        "sql_keyword_count":    count_matches(combined, SQL_KEYWORDS),
        "xss_keyword_count":    count_matches(combined, XSS_KEYWORDS),
        "path_traversal_count": count_matches(combined, PATH_TRAVERSAL_PATTERNS),
        "has_script_tag":       int("<script" in combined.lower()),
        "has_union_select":     int("union" in combined.lower() and "select" in combined.lower()),
        "has_comment_pattern":  int("--" in combined or "/*" in combined or "*/" in combined),
    }


# ══════════════════════════════════════════════════════════
# 파일 파싱
# ══════════════════════════════════════════════════════════
def parse_csic_file(file_path: Path) -> pd.DataFrame:
    with file_path.open("r", encoding="utf-8") as f:
        content = f.read()

    requests = re.findall(r"Start - Id:.*?\n(.*?)\nEnd - Id:", content, re.DOTALL)
    rows = []

    for req in requests:
        cls_match = re.search(r"class: (Valid|Attack)", req)
        label = 1 if cls_match and cls_match.group(1) == "Attack" else 0

        lines      = [l for l in req.splitlines() if l.strip()]
        first_line = next((l for l in lines if re.search(r"\b(GET|POST|PUT|DELETE)\b", l)), "")

        method_match   = re.search(r"\b(GET|POST|PUT|DELETE)\b", first_line)
        method         = method_match.group(1) if method_match else "UNKNOWN"
        full_url_match = re.search(r"http://[^\s]+", first_line)
        full_url       = full_url_match.group(0) if full_url_match else ""
        url_path, query_params = normalize_full_url(full_url)

        ua_match   = re.search(r"User-Agent: (.*)", req)
        user_agent = ua_match.group(1).strip() if ua_match else ""

        body_content = ""
        if "\n\n" in req:
            body_content = req.split("\n\n", 1)[1].strip()
            if body_content == "null":
                body_content = ""

        row          = build_feature_row(method, url_path, query_params, body_content, user_agent, full_url)
        row["class"] = label
        rows.append(row)

    return pd.DataFrame(rows)


def parse_capec_file(file_path: Path) -> pd.DataFrame:
    """
    data_capec_multilabel.csv → 23개 피처 DataFrame 변환

    컬럼 매핑:
        request_http_method  → method
        request_http_request → url_path + query_params  (?  기준 분리)
        request_body         → body_content             (NaN → "")
        request_user_agent   → user_agent               (NaN → "")
        000 - Normal         → class  (1 → 정상 0,  0 → 공격 1)
    """
    df_raw = pd.read_csv(file_path, low_memory=False)
    df_raw["class"] = (df_raw["000 - Normal"] == 0).astype(int)

    rows = []
    for _, r in df_raw.iterrows():
        method       = str(r.get("request_http_method") or "UNKNOWN").strip().upper()
        raw_request  = str(r.get("request_http_request") or "")
        body_content = "" if pd.isna(r.get("request_body")) else str(r["request_body"])
        user_agent   = "" if pd.isna(r.get("request_user_agent")) else str(r["request_user_agent"])
        url_path, query_params = normalize_full_url(raw_request)

        row          = build_feature_row(method, url_path, query_params, body_content, user_agent, raw_request)
        row["class"] = int(r["class"])
        rows.append(row)

    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════
# LabelEncoder
# ══════════════════════════════════════════════════════════
def fit_encoder(series: pd.Series) -> LabelEncoder:
    encoder = LabelEncoder()
    values  = sorted(set(series.fillna("").astype(str).tolist()) | {"UNKNOWN"})
    encoder.fit(values)
    return encoder


def apply_encoders(df: pd.DataFrame, encoders: dict[str, LabelEncoder]) -> pd.DataFrame:
    df = df.copy()
    for col, enc in encoders.items():
        known  = set(enc.classes_)
        values = df[col].fillna("").astype(str).where(lambda s: s.isin(known), "UNKNOWN")
        df[f"{col}_encoded"] = enc.transform(values)
    return df


# ══════════════════════════════════════════════════════════
# 데이터 증강 (CSIC 전용) — SMOTE-ENN
# ══════════════════════════════════════════════════════════
def augment_csic(X: pd.DataFrame, y: pd.Series) -> tuple[pd.DataFrame, pd.Series]:
    """
    CSIC 데이터 증강 — SMOTE-ENN (논문 기반 선택)

    참고 논문:
      - Akanksha & Manohar Naik (2024), SpringerLink: SMOTE-ENN for NIDS
        "SMOTE-ENN tackles imbalanced datasets and mitigates noise"
      - Enhancing intrusion detection with ResNet and SMOTE-ENN (2025), Springer:
        "XSS, SQL Injection 탐지 성능을 특히 크게 향상"
      - Behera et al. (2024), PLOS One: DDoS 탐지에서 99.97% 정확도 달성

    작동 원리 2단계:
      ① SMOTE : 공격 샘플(25,065건)을 인접 샘플 보간으로 정상(72,000건) 수준까지 생성
                 → 단순 SMOTE만 쓰면 경계 근처 노이즈 샘플도 같이 증폭되는 문제 발생

      ② ENN (Edited Nearest Neighbors) :
                 전체 데이터에서 주변 k개 이웃과 레이블이 다른 샘플을 제거
                 → 경계 근처의 노이즈·애매한 샘플을 정리
                 → 더 깨끗한 결정 경계 확보 → 모델 일반화 성능 향상

    기존 방식(SMOTE + Gaussian Noise)과 차이:
      기존: 생성 후 노이즈 추가 → 다양성 증가
      변경: 생성 후 노이즈 제거 → 품질 향상  ← 보안 로그 탐지에 더 적합
    """
    print("\n📈 CSIC 데이터 증강 중... (SMOTE-ENN)")
    print(f"   증강 전 : 총 {len(X):,}건  |  공격: {y.sum():,}  |  정상: {(y==0).sum():,}")

    smote_enn = SMOTEENN(
        sampling_strategy=1.0,  # 공격:정상 = 1:1 목표
        random_state=42,
    )
    X_aug, y_aug = smote_enn.fit_resample(X, y)

    print(f"   증강 후 : 총 {len(X_aug):,}건  |  공격: {y_aug.sum():,}  |  정상: {(y_aug==0).sum():,}")
    print(f"   (SMOTE로 공격 샘플 생성 → ENN으로 노이즈 샘플 제거)")

    return pd.DataFrame(X_aug, columns=X.columns), pd.Series(y_aug)


# ══════════════════════════════════════════════════════════
# 평가
# ══════════════════════════════════════════════════════════
def find_best_threshold(y_true: pd.Series, y_prob: np.ndarray) -> tuple[float, float]:
    best_threshold, best_f1 = 0.5, -1.0
    for threshold in np.arange(0.1, 0.91, 0.01):
        score = f1_score(y_true, (y_prob >= threshold).astype(int), zero_division=0)
        if score > best_f1:
            best_f1       = score
            best_threshold = float(round(threshold, 2))
    return best_threshold, best_f1


def print_metrics(title: str, y_true: pd.Series, y_prob: np.ndarray, threshold: float) -> None:
    y_pred          = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp  = confusion_matrix(y_true, y_pred).ravel()
    print(f"\n{title}")
    print(f"   Threshold : {threshold:.2f}")
    print(f"   Accuracy  : {accuracy_score(y_true, y_pred):.4f}")
    print(f"   Precision : {precision_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"   Recall    : {recall_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"   F1-Score  : {f1_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"   AUC-ROC   : {roc_auc_score(y_true, y_prob):.4f}")
    print(f"   FPR       : {fp / (fp + tn):.4f}")
    print(f"   FNR       : {fn / (fn + tp):.4f}")
    print(f"   Confusion : TN={tn:,}  FP={fp:,}  FN={fn:,}  TP={tp:,}")


# ══════════════════════════════════════════════════════════
# 피처 목록
# ══════════════════════════════════════════════════════════
FEATURES = [
    "method_encoded", "user_agent_encoded", "url_path_encoded", "file_extension_encoded",
    "url_len", "query_len", "body_len", "total_len",
    "path_depth", "param_count", "special_char_count", "special_char_ratio",
    "encoded_char_count", "digit_ratio", "alpha_ratio",
    "has_keywords_query", "has_keywords_body",
    "sql_keyword_count", "xss_keyword_count", "path_traversal_count",
    "has_script_tag", "has_union_select", "has_comment_pattern",
]
CATEGORICAL_COLUMNS = ["method", "user_agent", "url_path", "file_extension"]


# ══════════════════════════════════════════════════════════
# ① CSIC 2010 로딩 및 7:1:2 분리 (stratify 적용)
# ══════════════════════════════════════════════════════════
print("=" * 60)
print("📂 CSIC 2010 데이터 로딩 중...")
df_csic = pd.concat(
    [
        parse_csic_file(BASE_DIR / "cisc_normalTraffic_train.txt"),
        parse_csic_file(BASE_DIR / "cisc_normalTraffic_test.txt"),
        parse_csic_file(BASE_DIR / "cisc_anomalousTraffic_test.txt"),
    ],
    ignore_index=True,
)
print(f"   전체: {len(df_csic):,}건  |  공격: {df_csic['class'].sum():,}  |  정상: {(df_csic['class']==0).sum():,}")

print("\n✂️  CSIC 7:1:2 분리 중 (stratify 적용)...")
# 1단계: train 70% / 나머지 30%
df_csic_train, df_csic_temp = train_test_split(
    df_csic, test_size=0.30, random_state=42, stratify=df_csic["class"]
)
# 2단계: 나머지 30% → val 10% / test 20% (= 1:2)
df_csic_val, df_csic_test = train_test_split(
    df_csic_temp, test_size=2/3, random_state=42, stratify=df_csic_temp["class"]
)

print(f"   CSIC train : {len(df_csic_train):,}건  |  공격: {df_csic_train['class'].sum():,}  |  정상: {(df_csic_train['class']==0).sum():,}")
print(f"   CSIC val   : {len(df_csic_val):,}건   |  공격: {df_csic_val['class'].sum():,}   |  정상: {(df_csic_val['class']==0).sum():,}")
print(f"   CSIC test  : {len(df_csic_test):,}건  |  공격: {df_csic_test['class'].sum():,}  |  정상: {(df_csic_test['class']==0).sum():,}")


# ══════════════════════════════════════════════════════════
# ② CAPEC 7:1:2 분리 (stratify 적용)
# ══════════════════════════════════════════════════════════
print("\n📂 CAPEC Multilabel 데이터 로딩 중...")
df_capec = parse_capec_file(BASE_DIR / "data_capec_multilabel.csv")
print(f"   전체: {len(df_capec):,}건  |  공격: {df_capec['class'].sum():,}  |  정상: {(df_capec['class']==0).sum():,}")

print("\n✂️  CAPEC 7:1:2 분리 중 (stratify 적용)...")

# 먼저 train 70% / 나머지 30% 로 분리
df_capec_train, df_capec_temp = train_test_split(
    df_capec, test_size=0.30, random_state=42, stratify=df_capec["class"]
)
# 나머지 30% 를 val 10% / test 20% (= 1:2) 로 분리
df_capec_val, df_capec_test = train_test_split(
    df_capec_temp, test_size=2/3, random_state=42, stratify=df_capec_temp["class"]
)

print(f"   CAPEC train : {len(df_capec_train):,}건  |  공격: {df_capec_train['class'].sum():,}  |  정상: {(df_capec_train['class']==0).sum():,}")
print(f"   CAPEC val   : {len(df_capec_val):,}건   |  공격: {df_capec_val['class'].sum():,}  |  정상: {(df_capec_val['class']==0).sum():,}")
print(f"   CAPEC test  : {len(df_capec_test):,}건  |  공격: {df_capec_test['class'].sum():,}  |  정상: {(df_capec_test['class']==0).sum():,}")


# ══════════════════════════════════════════════════════════
# ③ LabelEncoder 학습 (CSIC train + CAPEC train 합쳐서 fit)
#    → val/test에서 나오는 미등록 값도 UNKNOWN 처리 가능
# ══════════════════════════════════════════════════════════
print("\n🔤 LabelEncoder 학습 중...")
df_for_encoding = pd.concat([df_csic_train, df_capec_train], ignore_index=True)
encoders = {col: fit_encoder(df_for_encoding[col]) for col in CATEGORICAL_COLUMNS}

# 6개 분할 데이터셋 모두 동일한 인코더로 변환
df_csic_train  = apply_encoders(df_csic_train,  encoders)
df_csic_val    = apply_encoders(df_csic_val,    encoders)
df_csic_test   = apply_encoders(df_csic_test,   encoders)
df_capec_train = apply_encoders(df_capec_train, encoders)
df_capec_val   = apply_encoders(df_capec_val,   encoders)
df_capec_test  = apply_encoders(df_capec_test,  encoders)
print("   완료")


# ══════════════════════════════════════════════════════════
# ④ CSIC train 증강 (SMOTE-ENN)
#    ※ val / test 는 원본 그대로 유지 — 증강 데이터 섞이면 평가 오염
# ══════════════════════════════════════════════════════════
X_csic_train = df_csic_train[FEATURES]
y_csic_train = df_csic_train["class"]

X_csic_train_aug, y_csic_train_aug = augment_csic(X_csic_train, y_csic_train)


# ══════════════════════════════════════════════════════════
# ⑤ 최종 데이터셋 조립
#    Train = CSIC train 증강본  +  CAPEC train
#    Val   = CSIC val (원본)    +  CAPEC val
#    Test  = CSIC test (원본)   +  CAPEC test
# ══════════════════════════════════════════════════════════
print("\n🔗 최종 데이터셋 조립 중...")

X_train = pd.concat([X_csic_train_aug,           df_capec_train[FEATURES]], ignore_index=True)
y_train = pd.concat([y_csic_train_aug,           df_capec_train["class"]],  ignore_index=True)

X_val   = pd.concat([df_csic_val[FEATURES],      df_capec_val[FEATURES]],   ignore_index=True)
y_val   = pd.concat([df_csic_val["class"],        df_capec_val["class"]],    ignore_index=True)

X_test  = pd.concat([df_csic_test[FEATURES],     df_capec_test[FEATURES]],  ignore_index=True)
y_test  = pd.concat([df_csic_test["class"],       df_capec_test["class"]],   ignore_index=True)

print(f"   Train : {len(X_train):,}건  |  공격: {y_train.sum():,}  |  정상: {(y_train==0).sum():,}")
print(f"   Val   : {len(X_val):,}건   |  공격: {y_val.sum():,}   |  정상: {(y_val==0).sum():,}")
print(f"   Test  : {len(X_test):,}건  |  공격: {y_test.sum():,}  |  정상: {(y_test==0).sum():,}")


# ══════════════════════════════════════════════════════════
# ⑥ 앙상블 모델 학습
# ══════════════════════════════════════════════════════════
print("\n🤖 앙상블 모델 학습 중...")
lgbm = lgb.LGBMClassifier(
    n_estimators=250, learning_rate=0.05,
    max_depth=-1, random_state=42,
    importance_type="gain", verbose=-1,
)
rf = RandomForestClassifier(
    n_estimators=150, class_weight="balanced",
    random_state=42, n_jobs=1,
)
extra = ExtraTreesClassifier(
    n_estimators=150, class_weight="balanced",
    random_state=42, n_jobs=1,
)
model = VotingClassifier(
    estimators=[("lightgbm", lgbm), ("random_forest", rf), ("extra_trees", extra)],
    voting="soft", weights=[2, 1, 1], n_jobs=1,
)
model.fit(X_train, y_train)
print("   학습 완료")


# ══════════════════════════════════════════════════════════
# ⑦ Threshold 최적화 (Val 기준)
# ══════════════════════════════════════════════════════════
print("\n🎯 Threshold 최적화 중 (CSIC+CAPEC val 기준)...")
y_val_prob     = model.predict_proba(X_val)[:, 1]
best_threshold, best_f1 = find_best_threshold(y_val, y_val_prob)
print(f"   최적 Threshold : {best_threshold:.2f}  (F1 = {best_f1:.4f})")

print_metrics("📊 Val 성능 (threshold=0.50)", y_val, y_val_prob, 0.5)
print_metrics(f"📊 Val 성능 (최적 threshold={best_threshold:.2f})", y_val, y_val_prob, best_threshold)


# ══════════════════════════════════════════════════════════
# ⑧ 최종 테스트 성능 측정 (Test 기준)
# ══════════════════════════════════════════════════════════
print("\n🏁 최종 테스트 성능 측정 (CSIC+CAPEC test 기준)...")
y_test_prob = model.predict_proba(X_test)[:, 1]
print_metrics(f"📊 Test 성능 (최적 threshold={best_threshold:.2f})", y_test, y_test_prob, best_threshold)


# ══════════════════════════════════════════════════════════
# ⑨ 번들 저장
# ══════════════════════════════════════════════════════════
bundle = {
    "model":              model,
    "encoders":           encoders,
    "features":           FEATURES,
    "categorical_columns": CATEGORICAL_COLUMNS,
    "threshold":          best_threshold,
    "model_type":         "soft_voting_lightgbm_randomforest_extratrees",
    "feature_version":    "ensemble_v4_both_split_smoteenn",
    "dataset":            "CSIC2010(7:1:2, train만 SMOTE-ENN 증강) + CAPEC_multilabel(7:1:2)",
    "augmentation":       "SMOTE-ENN on CSIC train only (imblearn.combine.SMOTEENN)",
}
joblib.dump(bundle, BUNDLE_PATH)

print(f"\n✅ 번들 저장 완료: {BUNDLE_PATH}")
print("   포함 항목: model / encoders / features / threshold / metadata")
print("=" * 60)
