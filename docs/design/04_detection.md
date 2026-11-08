# 04. 탐지 설계

한 HTTP 요청을 WAF와 AI가 각각 판정하고, WAF가 만든 `request_id`로 묶어 기록·알림·자동 차단까지 잇는 탐지 계층의 구조와 정책을 정리한다.

> 기준은 2026/11/08 `develop` 코드다. 탐지율·오탐률·공격 유형별 판정 평가는 보안 팀원 담당이며, 이 문서는 구조와 정책만 다룬다. 메시지 전달·재시도·알림 전송은 [03_event_pipeline.md](03_event_pipeline.md), 블랙리스트를 WAF 규칙으로 적용·보고하는 계약은 [05_waf_sync.md](05_waf_sync.md)를 본다.

## 1. 한눈에 보기

```text
요청 ─> WAF (Nginx + ModSecurity CRS, 일반 규칙 DetectionOnly) ─> JuiceShop
         │  $request_id 생성 → access.log · 감사 로그 · 응답 헤더에 같은 값
         ├─ access.log ─> log-topic ─> network_logs(request_id) ─> outbox ─> AI_new
         │                                     AI 판정 ─> ai-result-topic ─> detected_threats 'AI Detection'
         └─ 감사 로그(규칙 일치만) ─> waf-detection-topic ─> detected_threats 'WAF Detection' + waf_detections
                              │
              request_id로 연결 (request_correlations 요청별 잠금)
                              │
   WAF 또는 AI 탐지 → 기록 + 통합 알림
   같은 요청에서 WAF·AI 모두 탐지 + IP 일치 → ip_blacklist 자동 등록 → WAF 동기화 → 이후 요청 403
```

탐지는 요청 처리와 비동기다. 판정이 나올 때 원래 요청은 이미 JuiceShop에서 처리됐다. 자동·수동 블랙리스트 등록은 **이미 실행된 요청을 소급 차단하지 않고** 이후 요청만 막는다.

## 2. WAF 탐지

| 설정 | 값 (`compose.aws.yaml`, 로컬 `compose.yaml` 동일) | 의미 |
| --- | --- | --- |
| 이미지 | `owasp/modsecurity-crs:nginx` | OWASP CRS 포함 |
| `MODSEC_RULE_ENGINE` | `DetectionOnly` | 일반 규칙은 탐지·기록만 하고 요청을 통과시킨다 |
| `PARANOIA` / `BLOCKING_PARANOIA` | 2 / 1 | 탐지 범위 PL2. 차단 기준 PL1은 DetectionOnly라 실행되지 않음 |
| `ANOMALY_INBOUND` / `ANOMALY_OUTBOUND` | 5 / 4 | 이상 점수 임계값 (DetectionOnly라 차단하지 않음) |

- CRS와 `CUSTOM-001-ai-align.conf`의 `deny`는 DetectionOnly에서 실행되지 않는다.
- **블랙리스트 403은 별개다.** `CUSTOM-003`이 Include하는 동기화 규칙(id 20100)은 `ctl:ruleEngine=On`으로 그 요청에서만 엔진을 켜 403을 낸다. 수동 규칙은 `CUSTOM-002`(20001~20099)다. Spring 백엔드는 JuiceShop 요청을 직접 받는 차단 계층이 아니다([waf/README.md]).
- 차단된 요청(403)도 access 로그와 감사 로그(규칙 20100)로 수집되어 저장·AI 분석된다.

### 2.1 `request_id`와 요청 시작 시각

| 항목 | 정의 | 파일 |
| --- | --- | --- |
| `$request_id` | nginx가 요청마다 생성한다. 클라이언트가 보낸 ID는 쓰지 않는다 | nginx 내장 변수 |
| access JSON `request_id` | `log_format main`에 포함되어 `log-topic` 메시지가 된다 | [nginx-logging.conf.template] |
| ModSecurity `unique_id` | `modsecurity_transaction_id "$request_id"`로 감사 로그 `transaction.unique_id`를 같은 값으로 만든다 | [modsecurity.conf.template] |
| 응답 헤더 `X-Request-ID`, `X-DualGuard-Request-Start` | `more_set_headers`로 upstream·클라이언트 값 대신 WAF 값을 쓴다 | [nginx-logging.conf.template] |
| `$dg_request_start_epoch_s` | njs `requestStart` = `$msec - $request_time`(밀리초 해상도 UTC epoch). access JSON `request_start_epoch_s`에도 기록 | [headers.js], [nginx.conf.template] `js_set` |
| `$all_headers` | njs `dump`가 Cookie·Authorization·Set-Cookie·Proxy-Authorization·X-API-Key를 마스킹한 JSON | [headers.js] |

access JSON의 `test_run/phase/kind/seq`는 실험 관측용 표식이며 인증·IP 신뢰·차단 근거로 쓰지 않는다.

### 2.2 감사 이벤트 → `waf-detection-topic`

- ModSecurity 감사 로그(`MODSEC_AUDIT_LOG=/var/log/nginx/waf-audit.log`)를 Fluent Bit가 읽고 Lua `extract_detection`이 걸러 낸다([waf-detection.lua]).
- 규칙 ID가 있는 메시지만 남기고, 949110·959100은 이상 점수 합계로만 쓴다. 규칙이 없으면 레코드를 버린다. 요청·응답 본문, 헤더, 쿼리 문자열은 보내지 않는다.
- 출력 필드: `source`, `event_type`, `request_id`, `time`, `client_ip`, `method`, `path`(쿼리 제거), `status`, `anomaly_score`, `matched_rules[id, message, severity, matched_variable, attack_types]`.
- backend는 `WafDetectionEventDto`로 검증한다(필수 필드, `request_id` 255자 이하, 규칙 1개 이상). 잘못된 이벤트는 재시도 없이 DLT로 간다.
- [WafDetectionWriter]는 규칙 중 가장 심각한 ModSecurity severity로 위험도를 정한다(0~2 CRITICAL, 3 HIGH, 4 MEDIUM, 그 외 LOW, 없으면 UNKNOWN). 발생 시각(`EEE MMM d HH:mm:ss uuuu`, 초 단위)은 `WAF_EVENT_ZONE` 기준으로 UTC 변환하고, 해석에 실패하면 `NULL`로 두고 원문을 `event_time_raw`에 보존한다.
- 저장: `detected_threats`(`WAF Detection`, 설명 "WAF 규칙 N건 일치") + `waf_detections`(request_id, 규칙 JSON, 이상 점수 등). 같은 트랜잭션에서 통합 알림을 기록한다.

## 3. AI 탐지 (AI_new)

아래는 [AI_new main.py]와 [AI_new README]를 읽은 결과다. 서버 성능 작업에서는 AI_new 코드를 수정하지 않는다.

- 입력(outbox payload): `log_id`, `method`, `url_path`, `query_params`, `body_content`, `user_agent`, `ip_address`, `timestamp`.
- **1단계 규칙 게이트:** `rule_hits()`(SQL 논리 우회, 스캐너 UA 등)와 User-Agent 4,096자 초과는 임계값과 무관하게 공격이다. 점수는 `max(결합 확률, 0.90)`이다.
- **2단계 3모델 소프트보팅:** 로짓 공간 가중평균. 트랜스포머(바이트 단위) 0.05, 트리(HistGradientBoosting, 28피처, body 제거 입력) 0.85, 스키마 전문가(HistGradientBoosting, 12피처) 0.10. 임계값 0.9650.
- **3단계 근거 분해:** 공격 판정에만 수행한다(§4).
- 처리 방식: 시작 시 모델을 읽은 뒤 백그라운드 스레드 1개가 `ai-request-topic`을 한 건씩 처리한다(추론 → `ai-result-topic` 전송, 키 log_id → `flush()` → 다음 건). 그룹 `ai-service-group`, kafka-python 자동 커밋이다. 프로세스 수는 기본 1이다([03_event_pipeline.md](03_event_pipeline.md) §2.1).
- 처리 실패 메시지는 결과 없이 건너뛴다. 정상 결과로 위장하지 않는다. compose healthcheck는 `/health`의 `model_loaded`를 본다.
- HTTP `/predict`·`/predict/batch`는 같은 판정 로직의 보조 API다.

| 결과 필드 | 정상 | 공격 |
| --- | --- | --- |
| `threat_score` | 결합 확률 | 규칙 판정 0.90 이상, 모델 판정 0.965 이상 |
| `ip_address` | `"0.0.0.0"` | 입력 IP |
| `reason` | `"-"` | `[규칙] …` 또는 `[모델] …` (설명 생성 시 240자 이내) |
| `decision_source` | `null` | `"rule"` / `"model"` |
| `explanation` | `null` | 근거 분해 결과. 설명 실패 시 `null` |
| `log_id` | 입력 값 | 입력 값 |

backend [ThreatService]는 `ip_address`가 `0.0.0.0`이면 저장하지 않는다(`AI_RESULT_COMMITTED/NORMAL` 기록만). 공격이면 `detected_threats`에 `AI Detection`, 설명 `reason`, 위험도 `threat_score ≥ 0.8`이면 CRITICAL 아니면 HIGH로 저장한다. AI의 공격 점수는 0.90 이상이므로 실제로는 CRITICAL로 저장된다(코드에서 추론, 집계로 확인하지 않음).

## 4. AI 판정 근거 분해 (PR #113)

- [ensemble_explainer.py]의 `EnsembleExplainer`는 최종 로짓을 `base_logit + Σ contribution(트리 28 + 스키마 12) + transformer_logit + adjustment`로 나눈다. 트리·스키마 기여는 TreeSHAP 값에 가중치를 곱한 값이고, 트랜스포머는 한 항목으로 둔다.
- 공격 판정에만 계산하고 판정·점수는 바꾸지 않는다. 계산 시간은 탐지 1건당 p50 6.0ms, p95 6.6ms다(README census, 2026/10/23).
- `decision_source`: 규칙 게이트만 판정하면 `rule`, 3모델 로짓이 임계값 이상이면 `model`(규칙도 걸렸으면 `규칙도 일치: …`를 붙임).
- `review_recommended`: 규칙 없이 모델이 판정했고 트리 기여 중 시그니처형 피처 비율(`pattern_share`)이 0.5 미만이면 `검토 권장`을 붙인다. 기준 0.5는 평가 전에 정한 값이다.
- 실패 처리: 시작 시 "기준값 + SHAP 합 = 모델 로짓"(오차 1e-6 이내) 확인에 실패하거나 준비 중 예외가 나면 설명을 끈다. 요청별 설명 예외는 기존 reason으로 대체하고 결과는 그대로 보낸다.
- **backend는 새 필드를 저장하지 않는다.** [AiResponseDto]는 `log_id`·`threat_score`·`ip_address`·`reason`만 선언한다. [AiResultConsumer]는 Spring Boot가 자동 구성한 `ObjectMapper`를 주입받는다. 저장소에는 별도 `ObjectMapper` 빈이나 `spring.jackson` 설정이 없고, Spring Boot 기본값은 모르는 속성에서 실패하지 않는다. 그래서 `decision_source`·`explanation`은 무시되고 DB 스키마도 바뀌지 않는다.
- 화면까지 가는 근거는 `reason` 문자열(`detected_threats.description`)이다. [aiReason.js]가 이를 해석해 두 컴포넌트에 넘긴다. 접두어가 없는 과거 형식은 원문을 그대로 보여 준다.
  - [AiReason.js]: 위협 표의 판정 출처 배지, 검토 권장, 근거 목록.
  - [AiEvidence.js]: 로그 상세에서 근거 위치를 원본 요청 위에 표시한다. 글자 단위 기여도가 아니다.
- 한계: 기여도는 모델이 공격 쪽으로 기운 정도이지 공격 성공의 증거가 아니다. 경로 깊이 같은 데이터셋 지름길도 그대로 드러난다([AI_new README] 9장).

## 5. `request_id` 기반 상관관계

| 구성 | 내용 | 근거 |
| --- | --- | --- |
| UNIQUE 제약 | `network_logs.request_id`, `request_correlations.request_id`(PK), `waf_detections.request_id`, `waf_detections.threat_id` | [add-request-correlation.sql], [add-waf-detections.sql] |
| 대소문자 구분 | 세 `request_id` 컬럼 모두 `utf8mb4_0900_bin`. 통합 조회도 `CAST(... AS BINARY)`로 묶는다 | 같은 파일, [ThreatRepository] |
| 요청별 잠금 | `INSERT … ON DUPLICATE KEY UPDATE`로 `request_correlations` 행을 만들거나 기존 행을 잠근다. 트랜잭션이 끝날 때까지 같은 요청 처리가 직렬화된다 | [RequestCorrelationService] |
| 트랜잭션 | 상관관계 서비스는 `MANDATORY`라 호출자(`LogService.processRawLog`, `WafDetectionWriter.saveNewDetection`, `ThreatService.saveAiDetectedThreat`, 모두 READ_COMMITTED) 트랜잭션 안에서만 동작한다. 잠금·조회·저장·연결(WAF·AI 경로는 알림 기록·자동 차단 평가까지)이 한 트랜잭션이다 | 같은 클래스 |

로그와 WAF 이벤트는 서로 다른 토픽·컨슈머로 오므로 도착 순서가 바뀔 수 있다.

| 도착 상황 | 처리 |
| --- | --- |
| 로그 → WAF 이벤트 | Writer가 잠금 후 로그를 찾아 `log_id`를 연결해 저장한다 |
| WAF 이벤트 → 로그 | WAF 탐지를 `log_id = NULL`로 보존하고 가짜 로그 ID를 만들지 않는다. 로그 저장 때 `linkExistingWafDetection`이 연결한다 |
| 원본 로그가 끝내 없음 | WAF 탐지·알림은 그대로 남는다 |
| 같은 로그 재전달 | 잠금 후 기존 로그를 발견하면 연결만 확인하고 끝낸다 |
| 같은 WAF 이벤트 재전달·동시 처리 | 사전 확인 → 잠금 후 재확인 → UNIQUE 위반이면 다시 확인해 건너뛴다. 실제로 저장되지 않았으면 오류를 전파한다([WafDetectionService]) |
| AI 결과 | 로그 id로 로그를 찾고 `lockForAiResult`(request_id 잠금, 없으면 `network_logs` 행 `FOR UPDATE`) 후 중복을 확인하고 저장한다 |

## 6. 자동 차단 정책

현재 정책은 **WAF 또는 AI 탐지 시 기록·통합 알림**, **같은 요청에서 WAF와 AI 모두 탐지하고 IP도 일치할 때 자동 블랙리스트 등록**이다.

[AutoBlacklistPolicyService] `evaluate`(`MANDATORY`)는 아래를 모두 만족할 때만 등록한다.

1. 로그에 id와 `request_id`가 있다.
2. 로그 IP가 비어 있지 않고 `0.0.0.0`이 아니다.
3. 같은 `request_id`의 WAF 탐지가 있다.
4. 로그 IP와 WAF `client_ip`가 같다. 다르면 대상을 임의로 고르지 않고 경고 로그만 남긴다.
5. 같은 로그의 `AI Detection`이 있다.

- 호출 시점은 AI 탐지 저장 직후([ThreatService])와 로그가 연결된 WAF 탐지 저장 직후([WafDetectionWriter])다. 어느 쪽이 나중에 와도 평가된다. WAF가 로그보다 먼저 와도 AI 결과는 로그 저장 뒤에 오므로 AI 저장 때 평가된다.
- 원인 위협은 두 탐지 중 먼저 저장된(ID가 작은) 것이며 `ip_blacklist.source_threat_id`에 남긴다. 사유는 `[자동] 동일 요청에서 WAF·AI 모두 탐지 (WAF 위협 #…, AI 위협 #…)`, 위험도는 4다.
- [BlacklistService]는 이미 등록된 IP면 건너뛴다. 이 중복 방지는 애플리케이션 조회이며 `ip_blacklist.ip_address`에 UNIQUE 제약은 없다.
- DB 등록 뒤 WAF 동기화(기본 10초 주기)가 규칙을 적용한다. 등록, 적용 version 일치, 상태 보고 수신, 실제 403 확인은 서로 다른 단계다([05_waf_sync.md](05_waf_sync.md)).
- 알려진 한계([waf/README.md]): 만료(`expired_at`)를 반영하지 않는다. 차단된 요청도 로그·AI 탐지·알림이 쌓인다. 삭제 직후 늦게 도착한 AI 결과나 다음 동기화 전 공격으로 다시 등록될 수 있다.

## 7. 수동 등록·삭제

| API (`/api/v1/blacklist`) | 동작 |
| --- | --- |
| `GET` | 검색·페이지, `createdAt` 최신순 |
| `POST` | IP·사유·위험도로 등록. 원인 위협 없음(`source_threat_id = NULL`). 이미 있으면 400 |
| `DELETE /{id}` | 블랙리스트 행만 삭제(없으면 404, 성공 204). 원본 로그와 탐지 이력은 남는다 |

관리자 API는 세션 인증과 CSRF 보호를 쓴다([08_security.md](08_security.md)). 코드는 [BlacklistController], [BlacklistService]다.

## 8. 요청 단위 통합 위협 조회

- `GET /api/v1/threats/grouped` → [ThreatController] → `ThreatService.getGroupedThreats` → `ThreatRepository.findGroupedThreats`(native SQL).
- 묶는 키: `AI Detection`·`WAF Detection`은 `request:` + BINARY(`network_logs.request_id` 또는 `waf_detections.request_id`), 없으면 `log:<로그 id>`, 그것도 없으면 `threat:<위협 id>`다. 그 밖의 유형은 개별로 둔다.
- 먼저 묶은 뒤 출처(AI/WAF)·위험도·유형·위협 번호로 필터하고, 그룹의 최신 탐지 ID 내림차순으로 페이지를 나눈다. count 쿼리도 그룹 수를 센다. 그룹 건수와 개별 탐지 건수를 혼동하지 않는다.
- [GroupedThreatResponseDto]: `id`(그룹의 최초 위협), `logId`, `wafThreatId`·`aiThreatId`(실제 ID, WAF 상세는 `wafThreatId` 사용), `threatTypes`(먼저 저장된 순), `severity`(최고 위험도), `wafDescription`·`aiDescription`, `otherDescription`(HTTP 보조 API 등 다른 유형).
- 개별 탐지 목록은 `GET /api/v1/threats`다. 테이블 구조는 [07_database.md](07_database.md), API 계층은 [06_backend.md](06_backend.md)와 함께 본다.

## 결정 · 대안 · 근거

| 결정 | 검토한 대안 | 선택 근거 | 관련 문서·코드 |
| --- | --- | --- | --- |
| WAF가 만든 `request_id`로 상관관계 | IP·시각 조합, 클라이언트가 보낸 ID | WAF 감사 시각은 초 단위라 같은 IP의 초당 여러 요청을 구분하지 못하고, 두 이벤트의 도착 순서도 바뀐다. 클라이언트 ID는 위조할 수 있다. WAF 값 하나를 access·감사 로그 양쪽에 남긴다 | [nginx-logging.conf.template], [modsecurity.conf.template], [RequestCorrelationService] |
| 요청별 잠금 행 + UNIQUE + `MANDATORY` | 존재 확인만, 실패 후 재시도에 의존 | 같은 요청의 로그·WAF·AI가 서로 다른 컨슈머 스레드에서 동시에 처리된다. 잠금으로 직렬화하고 UNIQUE로 최종 방어하며, 호출자 트랜잭션과 분리되지 않게 한다 | [add-request-correlation.sql], [RequestCorrelationService] |
| 자동 차단은 같은 요청 WAF·AI 동시 탐지 + IP 일치 | WAF 단독, AI 단독, 점수 임계값 | 탐지기 하나만으로는 정상 입력도 공격으로 본다(로컬 시나리오 2026/11/02: 정상 입력 10건 중 WAF 오탐 7건, AI 0건. 정식 평가는 보안 팀원 담당). 잘못된 자동 차단은 정상 사용자를 막으므로, 단독 탐지는 기록·알림 후 관리자가 판단한다 | [AutoBlacklistPolicyService], [시나리오 카탈로그] |
| 일반 규칙 DetectionOnly + 블랙리스트만 403 | CRS 차단 모드 | WAF는 WAF·AI 비교를 위해 탐지·기록만 한다(waf/README). CRS 차단은 정상 입력의 오탐까지 막는다. 차단은 등록된 IP 목록으로 한정한다 | [waf/README.md], [05_waf_sync.md](05_waf_sync.md) |
| 판정 근거는 공격 판정에만, 실패 시 기존 reason | 모든 요청 설명, backend 스키마 확장 | 정상 요청 비용이 없고 판정이 바뀌지 않는다. 설명 실패가 탐지 발행을 막지 않는다. backend 변경 없이 배포할 수 있다(새 필드는 무시) | [ensemble_explainer.py], [AiResultConsumer] |
| 통합 목록은 요청 단위로 묶은 뒤 검색·페이지 | 개별 탐지 목록을 화면에서 병합 | 같은 요청의 WAF·AI가 두 행으로 보이거나 페이지 경계에서 갈라지는 문제를 막는다 | [ThreatRepository], [GroupedThreatResponseDto] |

[waf/README.md]: ../../waf/README.md
[nginx-logging.conf.template]: ../../waf/nginx-logging.conf.template
[nginx.conf.template]: ../../waf/nginx.conf.template
[modsecurity.conf.template]: ../../waf/modsecurity.conf.template
[headers.js]: ../../waf/njs/headers.js
[waf-detection.lua]: ../../waf/waf-detection.lua
[AI_new main.py]: ../../AI_new/main.py
[AI_new README]: ../../AI_new/README.md
[ensemble_explainer.py]: ../../AI_new/ensemble_explainer.py
[aiReason.js]: ../../frontend/src/utils/aiReason.js
[AiReason.js]: ../../frontend/src/components/AiReason.js
[AiEvidence.js]: ../../frontend/src/components/AiEvidence.js
[AiResponseDto]: ../../backend/src/main/java/com/example/security_log_system/dto/AiResponseDto.java
[AiResultConsumer]: ../../backend/src/main/java/com/example/security_log_system/kafka/AiResultConsumer.java
[ThreatService]: ../../backend/src/main/java/com/example/security_log_system/service/ThreatService.java
[WafDetectionService]: ../../backend/src/main/java/com/example/security_log_system/service/WafDetectionService.java
[WafDetectionWriter]: ../../backend/src/main/java/com/example/security_log_system/service/WafDetectionWriter.java
[RequestCorrelationService]: ../../backend/src/main/java/com/example/security_log_system/service/RequestCorrelationService.java
[AutoBlacklistPolicyService]: ../../backend/src/main/java/com/example/security_log_system/service/AutoBlacklistPolicyService.java
[BlacklistService]: ../../backend/src/main/java/com/example/security_log_system/service/BlacklistService.java
[BlacklistController]: ../../backend/src/main/java/com/example/security_log_system/controller/BlacklistController.java
[ThreatController]: ../../backend/src/main/java/com/example/security_log_system/controller/ThreatController.java
[ThreatRepository]: ../../backend/src/main/java/com/example/security_log_system/repository/ThreatRepository.java
[GroupedThreatResponseDto]: ../../backend/src/main/java/com/example/security_log_system/dto/GroupedThreatResponseDto.java
[add-request-correlation.sql]: ../db/add-request-correlation.sql
[add-waf-detections.sql]: ../db/add-waf-detections.sql
[시나리오 카탈로그]: ../testing/scenario_catalog.md
