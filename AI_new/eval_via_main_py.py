# -*- coding: utf-8 -*-
"""
AI_new/main.py를 통째로 그대로 써서(코드 재구현 없이) held-out TEST 세트 전체를
end-to-end로 돌리는 검증 스크립트.

main.py의 run_predict()를 직접 import해서 호출한다 -- 규칙 게이트, 트리, 스키마,
트랜스포머(락/검증 포함)까지 실제 서버가 요청 1건 처리할 때와 100% 동일한 코드
경로를 그대로 탄다. 카프카/HTTP 서버를 띄울 필요 없이, FastAPI startup 이벤트인
load_model()만 직접 한 번 호출해서 모델을 메모리에 올린 다음 매 요청을 함수 호출로
넣는다.

필요 파일 (모두 AI_new 폴더 기준):
  - AI_new/  전체 (main.py, features_v2.py, schema_expert.py, security_ai/, models/)
  - test.jsonl (raw 원문 test split, 225,822건) -- 이 스크립트와 같은 폴더에 두거나
    --test-jsonl 로 경로 지정

실행:
  cd AI_new
  pip install -r requirements.txt
  python eval_via_main_py.py --test-jsonl /path/to/test.jsonl
"""
import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    roc_auc_score, average_precision_score, f1_score,
    precision_score, recall_score, confusion_matrix,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))


def extract_user_agent(headers) -> str:
    for k, v in headers or []:
        if str(k).lower() == "user-agent":
            return v
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-jsonl", default="test.jsonl")
    ap.add_argument("--limit", type=int, default=None, help="디버그용 -- 앞에서 N건만")
    args = ap.parse_args()

    import main as ai_main  # AI_new/main.py

    print("[LOAD] main.load_model() 호출 (실제 서버 기동 시 하는 것과 동일) ...")
    ai_main.load_model()
    assert ai_main.models_ready, "모델 로딩 실패"
    print(f"  앙상블 가중치={ai_main.ENSEMBLE_WEIGHTS}  임계값={ai_main.ENSEMBLE_THRESHOLD}")

    y_true, y_score, y_source = [], [], []
    t0 = time.time()
    n = 0
    with open(args.test_jsonl, encoding="utf-8") as f:
        for line in f:
            if args.limit and n >= args.limit:
                break
            rec = json.loads(line)["record"]
            req = ai_main.HttpRequest(
                log_id=n + 1,  # PredictRequest.log_id는 ge=1 (0 이하 금지)
                method=rec.get("method") or "GET",
                url_path=rec.get("path") or "/",
                query_params=rec.get("query") or "",
                body_content=rec.get("body") or "",
                user_agent=extract_user_agent(rec.get("headers")),
            )
            resp = ai_main.run_predict(req)
            y_true.append(int(rec["label_binary"]))
            y_score.append(float(resp.threat_score))
            y_source.append(rec.get("source"))

            n += 1
            if n % 5000 == 0:
                elapsed = time.time() - t0
                print(f"  {n:,}건 처리 ({elapsed:.0f}s, {n/elapsed:.1f}건/s)")

    y_true = np.array(y_true)
    y_score = np.array(y_score)
    y_source = np.array(y_source)
    thr = ai_main.ENSEMBLE_THRESHOLD
    y_pred = (y_score >= thr).astype(int)

    auc = roc_auc_score(y_true, y_score)
    ap_ = average_precision_score(y_true, y_score)
    f1 = f1_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec_ = recall_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)

    print("\n" + "=" * 60)
    print(f"main.py 실제 서빙 코드로 돌린 TEST 세트 전체({n:,}건) 결과 (threshold={thr}):")
    print(f"  AUC={auc:.4f}  AP={ap_:.4f}  F1={f1:.4f}  Precision={prec:.4f}  Recall={rec_:.4f}")
    print(f"  Confusion Matrix [[TN FP] [FN TP]]:\n{cm}")
    print("-- source별 AP --")
    for src in sorted(set(y_source)):
        m = y_source == src
        if len(set(y_true[m])) < 2:
            continue
        print(f"  {src:12s} n={m.sum():>7,}  AP={average_precision_score(y_true[m], y_score[m]):.4f}")

    print("\n비교 참고 (ai_team_sync/ensemble_results/ensemble_final_summary.json, "
          "사전 계산된 확률로 나온 test 결과): AUC=0.9947  AP=0.9847")
    print("(위 값과 거의 같게 나오면 main.py 코드 경로가 정확하다는 뜻)")

    with open("eval_via_main_py_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "n": int(n), "threshold": thr,
            "auc": auc, "ap": ap_, "f1": f1, "precision": prec, "recall": rec_,
            "confusion_matrix": cm.tolist(),
        }, f, ensure_ascii=False, indent=2)
    print("\n[SAVE] eval_via_main_py_results.json")


if __name__ == "__main__":
    main()
