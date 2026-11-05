# 이전 AI 모델(v1) 기록

이전 `AI/` 디렉터리(FastAPI 서버 + RandomForest·ExtraTrees·XGBoost·HistGradientBoosting 4모델 소프트보팅)를
저장소에서 제거하면서, 현재 모델과 비교하는 데 필요한 기록만 옮겨 둔 폴더다.
현재 AI 서비스는 [`AI_new/README.md`](../../../AI_new/README.md)를 본다.

| 문서 | 내용 | 현재 모델과 비교할 때의 의미 |
| --- | --- | --- |
| [model-pipeline.md](model-pipeline.md) | 모델 선정, Optuna 튜닝, 가중치 9:9:6:2, 임계값 0.6321, 테스트 성능 | 3모델(트랜스포머·트리·스키마)로 교체하기 전 기준선 |
| [threshold-experiment.md](threshold-experiment.md) | 임계값 0.50~0.95별 정확도·F1·오탐률·미탐률 | 채택 임계값 0.6321의 오탐률 6.20% — 오탐 감소 작업의 이전 상태 |
| [reason-verification.md](reason-verification.md) | 2026-07-14 판정 사유(`reason`) 출력 검증 7건 | 키워드 나열식 사유. 2번 사례(특수문자 과다, 0.4162점)는 사유가 `-`로 비어 있다 — 현재 판정 근거 분해(TreeSHAP)와의 비교 대상 |

## 읽을 때 주의

- 본문은 당시 기록을 그대로 보존했다. 파일 이름만 바꿨고 표현과 수치는 현재 기준으로 고치지 않았다.
- 수치는 당시 학습 데이터셋(CSIC 2010, CAPEC 다중 레이블)에서 측정한 값이다. 현재 평가와 데이터·방식이 달라 직접 비교할 수 없다.
- 본문에 나오는 `model_selection.py`, `model_tuning_extreme.py`, `weight_optimizer.py`, `main.py`는 이 폴더에 없다.
  제거 전 커밋 `39de94d8`의 `AI/`에서 볼 수 있다(예: `git show 39de94d8:AI/weight_optimizer.py`).
  모델 번들(`model_bundle_ultimate.pkl`)은 원래 저장소에 포함되지 않았다.
- 7월 진행 보고서(`AI/AI_July.md`: v1 피처 23개 명세, 데이터셋 설명)는 옮기지 않았다. 같은 커밋에서 볼 수 있다.
