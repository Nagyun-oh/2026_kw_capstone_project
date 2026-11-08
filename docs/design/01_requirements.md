# 01. 요구사항

이 문서는 DualGuard의 기능·비기능 요구사항을 구현 위치와 검증 근거·측정 결과에 연결한다.

최종 확인: 2026/11/08 · 측정값은 [EC2 목차](../testing/ec2/README.md)의 실제 회차 결과다.

## 1. 읽는 법

- **목표**는 측정 전에 정한 값이다. 결과를 본 뒤 소급해서 바꾸지 않는다([P8](../testing/ec2/P8.md)).
- **측정**은 EC2 t3.large(2 vCPU)에서 실제로 잰 값이다. 로컬 결과를 EC2 결과로 쓰지 않는다.
- 아래 Java 클래스는 `backend/src/main/java/com/example/security_log_system/` 아래에 있다. 테스트는 같은 패키지 구조의 `backend/src/test/`에 있다.
- 백엔드 단위 테스트 통과는 실제 통합 동작 검증과 구분한다. 통합 근거는 EC2·로컬 회차 보고서로 따로 적는다.

## 2. 기능 요구사항

| ID | 요구사항 | 구현 위치 | 검증 근거 |
| --- | --- | --- | --- |
| FR-01 | **로그 수집**: WAF를 지난 HTTP 요청의 접근 로그를 WAF가 만든 `request_id`와 함께 저장한다. 같은 `request_id`는 한 번만 저장한다 | [nginx-logging.conf.template](../../waf/nginx-logging.conf.template) → [fluent-bit.conf](../../waf/fluent-bit.conf)(`log-topic`) → `kafka/LogKafkaConsumer` → `service/LogService` | `LogConsumerTest`, `LogServiceTest`. EC2 정식 회차의 중복 로그 0건 |
| FR-02 | **로그 조회·검색**: 로그 ID·IP·메서드·상태 코드 조건과 페이지로 조회하고, 번호로 단건을 연다 | `GET /api/v1/logs`, `GET /api/v1/logs/{id}` — `controller/LogController`, `dto/LogSearchCondition`, `repository/LogSpecification` | `LogControllerTest`. [트러블슈팅_3](<../testing/ec2/트러블슈팅_3(상세본).md>): `created_at` 인덱스 후 부하 중 목록 조회 평균 127.7 → 0.7ms |
| FR-03 | **AI 분석 요청**: 저장한 로그마다 AI 요청을 같은 트랜잭션의 outbox에 남기고, 커밋 뒤 `ai-request-topic`으로 발행한다 | `LogService` → `service/AiRequestOutboxService` → `AiRequestOutboxDispatcher`·`AiRequestOutboxPublisher`(+`AiRequestOutboxWakeup`) | `AiRequestOutboxPublisherTest`, `AiRequestTopicConfigTest`. [로컬 복구 검증](../testing/local/recovery-verification.md) 7사례 PASS |
| FR-04 | **AI 탐지 저장**: 공격 판정만 `AI Detection`으로 저장한다. 정상 결과는 저장하지 않고 중복 결과는 건너뛴다. 처리 실패는 재시도 후 DLT로 보낸다 | `kafka/AiResultConsumer` → `ThreatService.saveAiDetectedThreat`, `config/PipelineKafkaErrorConfig` | `AiResultConsumerTest`, `ThreatServiceTest`, `PipelineKafkaErrorConfigTest` |
| FR-05 | **WAF 탐지 저장**: ModSecurity 감사 로그의 탐지를 `WAF Detection`으로 저장한다. 원본 로그보다 먼저 와도 보존하고 가짜 로그 ID를 만들지 않는다 | [waf-detection.lua](../../waf/waf-detection.lua) → `waf-detection-topic` → `kafka/WafDetectionConsumer` → `WafDetectionService`·`WafDetectionWriter` | `WafDetectionConsumerTest`, `WafDetectionServiceTest`, `WafDetectionWriterTest`. Consumer는 `WAF_CONSUMER_ENABLED`로 켜며 EC2 실행값 true 확인([P0](../testing/ec2/P0.md)) |
| FR-06 | **요청 단위 통합 위협 목록**: 같은 요청의 WAF·AI 탐지를 한 행으로 묶은 뒤 검색·페이지 처리한다. WAF 상세는 실제 WAF 탐지 ID로 연다 | `GET /api/v1/threats/grouped`, `GET /api/v1/threats/{threatId}/waf-detail` — `ThreatController`, `ThreatRepository`, `GroupedThreatResponseDto`, `WafDetectionController` | `WafDetectionQueryServiceTest`. 그룹 조회 전용 단위 테스트는 없음. EC2 [대표 행 재확인 PASS](../testing/ec2/runs/20261105T205423+0900-ec2-table-recheck-r01.md)와 정식 회차마다 대표 행 확인 |
| FR-07 | **커밋 후 통합 알림**: 탐지와 알림 대기 기록을 같은 트랜잭션에 저장하고, 커밋 뒤 STOMP `/topic/threats`로 전송·재시도한다. 같은 요청의 두 출처는 같은 alertId로 갱신해 중복 팝업을 막는다 | `RequestAlertService`, `RequestAlertDispatcher`, `RequestAlertPublisher`, `RequestAlertWakeup`, `AfterCommitDispatchTrigger`, [useWebSocket.js](../../frontend/src/hooks/useWebSocket.js) | `AfterCommitDispatchTriggerTest`, `AfterCommitWakeupHookTest`, `AfterCommitWakeupWiringTest`, `useWebSocket.test.js`. EC2 probe 두 출처 수신·DOM 확인 |
| FR-08 | **수동 블랙리스트**: 관리자가 IP를 등록·조회·삭제한다. 삭제해도 원본 로그·탐지 이력은 남는다 | `GET`·`POST /api/v1/blacklist`, `DELETE /api/v1/blacklist/{id}` — `BlacklistController`, `BlacklistService` | `BlacklistControllerTest`, `BlacklistServiceTest`, `IpAddressValidatorTest` |
| FR-09 | **자동 블랙리스트**: 같은 요청에서 WAF·AI가 모두 탐지하고 IP도 같으면 위험도 4로 자동 등록한다. 원인 위협은 먼저 저장된 탐지다 | `service/AutoBlacklistPolicyService`, `RequestCorrelationService`(요청별 잠금) | `AutoBlacklistPolicyServiceTest`: 한쪽만 탐지·다른 요청·IP 불일치는 등록 안 함, 도착 순서와 무관하게 등록 |
| FR-10 | **WAF 차단 동기화**: WAF가 10초마다 블랙리스트 스냅샷을 토큰 인증으로 받아 적용하고, 등록 IP 요청만 403으로 막는다. 조회·검증·reload 실패 시 마지막 정상 설정을 유지한다 | [blacklist-sync.sh](../../waf/sync/blacklist-sync.sh), `GET /internal/waf/blacklist` — `WafSyncController`, `BlacklistSnapshotService`, `WafSyncTokenFilter` | [test_blacklist_sync.py](../../waf/tests/test_blacklist_sync.py), `BlacklistSnapshotServiceTest`, `WafSyncControllerTest`. 실제 403·해제는 로컬에서 확인([waf/README.md](../../waf/README.md) 2026/10/20~21) |
| FR-11 | **WAF 동기화 상태 표시**: WAF의 적용 결과 보고를 받아 적용 확인·반영 대기·동기화 실패·상태 미확인으로 표시한다. 보고가 60초 넘게 없으면 미확인이다 | `POST /internal/waf/sync-status`, `GET /api/v1/waf/sync-status` — `WafSyncStatusService`, `WafSyncStatusDto`, [WafSyncStatusPanel.js](../../frontend/src/components/WafSyncStatusPanel.js) | `WafSyncControllerTest`(보고 수신·토큰). 화면 상태 계산 전용 테스트는 확인되지 않음. EC2 회차마다 적용 보고 확인 |
| FR-12 | **관리자 인증**: 관리자 API는 세션 + CSRF, `ADMIN` 권한만 허용한다. STOMP 연결·`/topic/threats` 구독도 관리자만 가능하다. 내부 API는 `X-WAF-Sync-Token` 전용이다. 로그인은 사용자 이름별로 15분 안에 5번 실패하면 15분 동안 429로 거절한다 | `config/SecurityConfig`, `WebSocketSecurityConfig`, `WafSyncSecurityConfig`, `AuthController`, `AuthService` | `AuthControllerTest`, `AuthServiceTest`, `WafSyncControllerTest`(토큰과 관리자 세션 상호 대체 불가). EC2 [P7](../testing/ec2/P7.md) 실제 관리자 폼 로그인 |
| FR-13 | **AI 판정 근거 표시**: AI가 판정 출처(`[규칙]`/`[모델]`)와 기여 상위 피처·근거 문자열을 `reason`으로 보낸다. 백엔드는 이를 탐지 설명으로 저장하고, 화면은 위협 표와 로그 상세에 출처 배지·근거 목록·근거 위치를 표시한다. 판정 자체는 바꾸지 않는다 | [ensemble_explainer.py](../../AI_new/ensemble_explainer.py), `ThreatService`(설명 = `reason`), [AiReason.js](../../frontend/src/components/AiReason.js)·[AiEvidence.js](../../frontend/src/components/AiEvidence.js), `utils/aiReason.js`·`aiEvidence.js` | [test_explanation.py](../../AI_new/tests/test_explanation.py), `aiReason.test.js`, `aiEvidence.test.js`. PR #113으로 `develop` 머지. EC2 반영·실환경 확인은 미확인 |

FR-13 참고: AI 응답의 `decision_source`·`explanation` 필드는 현재 백엔드가 저장하지 않는다. `AiResponseDto`는 `log_id`·`threat_score`·`ip_address`·`reason` 네 필드만 받는다.

## 3. 비기능 요구사항

목표는 [P8](../testing/ec2/P8.md)에서 2026/11/05에 확정했다. 1·3·5 RPS 기준선은 개선 전 배포(2026/11/05~06), 11·13 RPS는 트러블슈팅_1~7 반영 배포(2026/11/08)에서 쟀다.

| ID | 항목 | 목표 | 측정 결과 | 판정 |
| --- | --- | --- | --- | --- |
| NFR-01 | AI 서버 경로 지연(WAF 요청 시작 → AI 결과 커밋, NORMAL 포함) | p95 ≤ 3,000ms | 합산 p95: 1 RPS 1,004 · 3 RPS 1,017 · 5 RPS 1,049ms → 개선 후 5 RPS 348.3ms(r33~r35) · 11 RPS 851.7ms · 13 RPS 2,040.4ms | 13 RPS까지 충족 |
| NFR-02 | WAF 서버 경로 지연(WAF 요청 시작 → WAF 탐지 커밋) | p95 ≤ 3,000ms | 1 RPS 608 · 3 RPS 614 · 5 RPS 541ms, 13 RPS 239ms | 충족 |
| NFR-03 | 정합성 | 송신·DB·AI 완료를 run ID·`requestId`로 대조, 중복 로그·탐지·커밋 계측 0건 | 정식 1·3·5 RPS 측정 3,240건 모두 저장·AI 완료. 11·13 RPS 6회도 측정 요청 전부 저장·AI 완료 | 충족 |
| NFR-04 | 적체 해소 | 부하 종료 후 60초 안에 AI 완료·probe DOM·필수 Kafka 4개 경로 lag 0(10초 이상 간격 연속 2표본) | 정식 PASS 회차 모두 충족. 예: 5 RPS r33~r35 약 19.5초 | 충족 |
| NFR-05 | 알림 전달 | probe의 WAF·AI 두 출처 전송·브라우저 수신·DOM, 같은 alertId 중복 팝업 없음 | 1·3·5 RPS 단계마다 probe 36건 확인 | 충족 |
| NFR-06 | 반복 재현성 | 같은 단계 정식 3회가 모두 PASS여야 단계 PASS. pilot은 합산 안 함 | 1·3·5 RPS 각 3/3, 11·13 RPS 각 3/3 | 충족 |
| NFR-07 | 알림 발행 지연(트러블슈팅_5 사례 목표) | 탐지 커밋 → 알림 전송 시작 p95 ≤ 50ms | AI 17.1ms · WAF 14.7ms(5 RPS r27~r29) | 충족 |
| NFR-08 | 화면 알림 표시(트러블슈팅_4·5 사례 목표) | 공격 → AI 알림 표시 p95 < 1초 | 5 RPS: 1,329.7ms(r27~r29) → 984.1ms(r30~r32) → 821.3ms(r33~r35, 현재 기준선). 11 RPS 1,212.3ms · 13 RPS 1,662.6ms(각 3회). 단계당 36표본, PC 브라우저 포함 | 5 RPS 충족, 11·13 RPS 미달(참고값) |
| NFR-09 | 자원 안전 | 호스트 가용 메모리 1GiB 미만 15초 지속 시 중단 | 13 RPS 가용 메모리 최소 4.49GB | 충족 |
| NFR-10 | 차단 반영 주기 | 동기화·보고 10초, stale 60초(설정 기본값) | 로컬: 등록 후 약 3~4초 안에 적용·403, 삭제 후 약 7초에 해제 | 로컬 확인. EC2 403은 미검증(측정 중 발생기 IP 제외) |

서버 지연은 같은 EC2 호스트 시계(WAF 시작 시각, `DG_TRACE`)로 계산한다. PC HTTP·브라우저 시간은 따로 관측하며 네트워크 시간을 추정해 빼지 않는다. 표본이 적은 p99는 참고값이다.

## 4. 처리 용량 (측정 결과, 목표 아님)

[단계 부하 계획](../testing/ec2/step-load-plan.md) 4-5절과 [트러블슈팅_8](<../testing/ec2/트러블슈팅_8(상세본).md>)의 결과다.

| 관측 | 값 |
| --- | --- |
| 11·13 RPS 정식 반복 | 각 3/3 PASS, 한계 신호 없음(측정 도구 부담 축소 후, 계약 개정 6) |
| 서버 p95 AI 추이 | 5 → 11 → 13 RPS에서 268.5(r36 1회) → 851.7 → 2,040.4ms |
| 지연 knee | 11~13 RPS. SLO(p95 3초)를 넘는 처리 한계는 13 RPS보다 위이며 미측정 |
| 호스트 CPU 평균 | 5 RPS 47.1% · 11 RPS 73.4~75.2% · 13 RPS 80.7~82.0% |
| 지연이 쌓이는 구간 | AI 구간(로그 커밋 → AI 결과 커밋). 13 RPS p95 1,880.8ms, 같은 조건 로그 수집 203.8ms·WAF 경로 239ms |
| 제약 | AI 소비자 병렬화(파티션 2 + 프로세스 2) 실험에서 지연이 줄지 않아 가설 기각. 제약은 2 vCPU 호스트 CPU다 |

앞선 13 RPS 1회 FAIL(p95 3,128.8ms)은 측정 도구 부담(부하 중 lag CLI·전체 스캔 수집 쿼리)이 컸던 결과다. 원본·판정은 보존하고 위 반복 결과와 섞지 않는다.

## 5. 요구사항 → 검증 방법 → 결과

| 요구사항 | 검증 방법 | 결과 |
| --- | --- | --- |
| FR-01, FR-03, FR-04 | 백엔드 단위 테스트, 격리 DB·Kafka 복구 검증, 로컬·EC2 E2E 요청 집합 대조 | [복구 검증](../testing/local/recovery-verification.md) · [로컬 1건/초 3회](../testing/local/20261103-rps1-baseline-review.md) · [EC2 1·3·5 비교](../testing/ec2/runs/20261106-ec2-1-3-5rps-comparison.md) |
| FR-02 | 컨트롤러 테스트, EC2 DB 관측·실행 계획 비교 | [트러블슈팅_3](<../testing/ec2/트러블슈팅_3(상세본).md>) |
| FR-05, FR-06 | 단위 테스트, EC2 probe의 WAF 탐지·대표 위협 행 확인 | [P7](../testing/ec2/P7.md) · [대표 행 재확인](../testing/ec2/runs/20261105T205423+0900-ec2-table-recheck-r01.md) |
| FR-07, NFR-05 | 커밋 후 깨우기 테스트, 프론트 hook 테스트, 실제 브라우저 수신·DOM | [P8 pilot r03](../testing/ec2/runs/20261105T215318+0900-ec2-pilot-r03.md) · [트러블슈팅_5](<../testing/ec2/트러블슈팅_5(상세본).md>) |
| FR-08, FR-09 | 정책 단위 테스트(탐지 조합·도착 순서·IP 불일치) | `AutoBlacklistPolicyServiceTest`, `BlacklistServiceTest` |
| FR-10, FR-11, NFR-10 | WAF 스크립트 단위 테스트, 토큰 API 테스트, 로컬 실제 Nginx 403 확인 | [waf/README.md](../../waf/README.md) · [05 WAF 동기화](05_waf_sync.md) |
| FR-12 | 인증·토큰 테스트, EC2 관리자 폼 로그인·STOMP 준비 | [P7](../testing/ec2/P7.md) · [08 보안](08_security.md) |
| FR-13 | AI 설명 테스트(pytest), 프론트 파서 테스트 | [AI_new/README.md](../../AI_new/README.md) 9장 · [04 탐지](04_detection.md) |
| NFR-01~04, NFR-06 | EC2 정식 1·3·5 RPS·120초·3회 | [1 RPS](../testing/ec2/runs/20261105-ec2-1rps-baseline-review.md) · [3 RPS](../testing/ec2/runs/20261105-ec2-3rps-baseline-review.md) · [5 RPS](../testing/ec2/runs/20261106-ec2-5rps-baseline-review.md) |
| NFR-01, 처리 용량 | EC2 단계 부하 11·13 RPS 각 3회 | [단계 부하 4-5절](../testing/ec2/step-load-plan.md) · [트러블슈팅_8](<../testing/ec2/트러블슈팅_8(상세본).md>) |
| NFR-07, NFR-08 | 같은 이미지에서 깨우기 끔·켬 5 RPS 각 3회 | [트러블슈팅_5](<../testing/ec2/트러블슈팅_5(상세본).md>) |
| NFR-09 | 실행기 자원 감시·중단 조건 | [P8](../testing/ec2/P8.md) · [트러블슈팅_8](<../testing/ec2/트러블슈팅_8(상세본).md>) |

## 결정 · 대안 · 근거

| 결정 | 검토한 대안 | 선택 근거 | 관련 문서·코드 |
| --- | --- | --- | --- |
| 서버 경로 p95 3초를 공학적 목표로 고정 | 산업 SLA 수치 차용, 결과를 보고 목표 조정 | 수초 안의 모니터링이 목적이다. 목표는 실행 전에 고정하고, 바꿀 때는 새 버전과 이유를 남겨 비교 조건을 분리한다 | [P8](../testing/ec2/P8.md) |
| 서버 지연과 PC·브라우저 지연을 분리 | PC에서 잰 종단 지연 하나로 판정 | 두 시계를 직접 빼면 오프셋·드리프트가 섞인다. 서버 구간은 같은 호스트 시계로 계산하고, 화면 표시는 별도 관측으로 둔다 | P8 "외부 지연", [트러블슈팅_8](<../testing/ec2/트러블슈팅_8(상세본).md>) 1부 |
| 자동 차단은 같은 요청의 WAF AND AI + IP 일치 | WAF 또는 AI 단독 탐지로 차단, 같은 IP의 다른 요청 결과 합산 | 정상 입력 10건 중 WAF 오탐 7건을 AI가 모두 정상으로 판정했다. 다른 요청을 IP만으로 합치면 자동 차단 근거가 흐려진다 | [시나리오 카탈로그](../testing/scenario_catalog.md) 8.5절, `AutoBlacklistPolicyService`, [테스트 가이드](../testing/README.md) |
| 처리 용량은 목표가 아니라 측정 결과로 기록 | 목표 RPS를 미리 정하고 맞추기 | 같은 사양에서 한계와 병목을 찾는 것이 목적이다. 한계 신호 FAIL은 실험 실패가 아니라 측정 결과다 | [단계 부하 계획](../testing/ec2/step-load-plan.md) 1·4절 |
