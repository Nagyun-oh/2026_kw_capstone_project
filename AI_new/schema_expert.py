# -*- coding: utf-8 -*-
"""
schema_expert.py — 앙상블 3번째 멤버: '구조/스키마' 전문가

내용(키워드·문자 비율)이 아니라 **애플리케이션 구조**만 본다.
  · 이 경로를 정상 트래픽에서 본 적 있는가
  · 이 경로에 이 파라미터 이름 조합이 오는 게 정상인가
  · 처음 보는 파라미터 이름이 몇 개인가
  · 값의 형태(길이·숫자 여부·인코딩)가 평소와 같은가

내용 모델(HGB v2) 및 문자열 모델(Transformer)과 표현이 겹치지 않는 것이 설계 목적이다.
실측 상관계수 0.65 (트리 6종끼리는 0.97~0.997).

★ 스키마 사전은 **보호 대상 애플리케이션의 정상 트래픽**으로 만들어야 한다.
  혼합 학습 코퍼스로 만들면 434,035개 경로 = 108MB가 되지만,
  단일 앱(예: CSIC tienda1)은 1,159개 경로 = 수십 KB에 불과하다.
  이것이 상용 WAF의 positive security model과 같은 방식이다.
"""
import numpy as np
from collections import defaultdict

FEATURES = ["path_known", "paramset_known", "log_path_freq", "log_paramset_freq",
            "n_unknown_params", "frac_unknown", "n_params", "max_val_len",
            "mean_val_len", "n_numeric_vals", "n_encoded_vals", "path_depth"]


def parse_params(query, body="", cap=65536):
    out = []
    for blob in (query or "", body or ""):
        for part in blob[:cap].split("&"):
            if "=" in part:
                k, _, v = part.partition("=")
                out.append((k[:64], v))
    return out


def build_dictionary(requests):
    """requests: (path, query, body) 반복자. 보호 대상 앱의 **정상 트래픽**만 넣을 것."""
    path_cnt = defaultdict(int); pset_cnt = defaultdict(int); path_params = defaultdict(set)
    for path, query, body in requests:
        ps = parse_params(query, body)
        names = ",".join(sorted({k for k, _ in ps}))
        path_cnt[path] += 1
        pset_cnt[(path, names)] += 1
        if names:
            path_params[path].update(names.split(","))
    return {"path_cnt": dict(path_cnt),
            "pset_cnt": {f"{p}\t{n}": c for (p, n), c in pset_cnt.items()},
            "path_params": {k: sorted(v) for k, v in path_params.items()}}


def build_row(path, query, body, D):
    path = path or ""
    ps = parse_params(query, body)
    names = ",".join(sorted({k for k, _ in ps}))
    vals = [v for _, v in ps]
    vl = [len(v) for v in vals] or [0]
    known = set(D["path_params"].get(path, ()))
    nunk = 0 if not names else (len(names.split(",")) if path not in D["path_params"]
                                else sum(1 for k in names.split(",") if k not in known))
    npar = len(names.split(",")) if names else 0
    return {
        "path_known": 1.0 if path in D["path_cnt"] else 0.0,
        "paramset_known": 1.0 if f"{path}\t{names}" in D["pset_cnt"] else 0.0,
        "log_path_freq": float(np.log1p(D["path_cnt"].get(path, 0))),
        "log_paramset_freq": float(np.log1p(D["pset_cnt"].get(f"{path}\t{names}", 0))),
        "n_unknown_params": float(nunk),
        "frac_unknown": float(nunk / npar) if npar else 0.0,
        "n_params": float(len(ps)),
        "max_val_len": float(max(vl)),
        "mean_val_len": float(sum(vl) / len(vl)),
        "n_numeric_vals": float(sum(1 for v in vals if v and v.replace(".", "").isdigit())),
        "n_encoded_vals": float(sum(1 for v in vals if "%" in v or "+" in v)),
        # 주의: 학습 스크립트(AI_v0/tune_schema_expert.py, ai_team_sync/ensemble_results/
        # build_ensemble_probs.py)의 공식과 반드시 일치시킬 것 -- 예전엔 "비어있지 않은
        # 세그먼트 개수"(len([s for s in path.split("/") if s]))였는데, 이건 학습 때 쓴
        # max(0, path.count("/") - 1)과 대부분의 경로에서 1씩 어긋나서 스키마 모델이 학습 때
        # 보지 않은 입력 분포를 받는 train/serve skew였다(2026-09-20, Codex 리뷰로 발견).
        "path_depth": float(max(0, path.count("/") - 1)),
    }


def to_vector(row):
    return np.array([[row[f] for f in FEATURES]], dtype=np.float32)


# ── 앙상블 결합 ────────────────────────────────────────────────
def _logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def soft_vote(probas, weights=None):
    """소프트 보팅은 **로짓 공간에서** 평균낸다.
    확률 공간 평균은 자신감 큰 모델이 지배해 약한 전문가의 기여가 사라진다.
    실측: 확률평균 F1 0.9228 vs 로짓평균 F1 0.9294 (내용 단독 0.9237)."""
    probas = np.asarray(probas, dtype=np.float64)
    w = np.ones(len(probas)) if weights is None else np.asarray(weights, dtype=np.float64)
    w = w / w.sum()
    z = np.tensordot(w, _logit(probas), axes=1)
    return 1.0 / (1.0 + np.exp(-z))
