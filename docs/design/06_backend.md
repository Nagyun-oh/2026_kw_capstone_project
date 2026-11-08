# 백엔드 설계

이 문서는 Spring Boot 백엔드의 패키지·계층 구조와 트랜잭션·인증·시간·발행기·오류 처리 규칙이 왜 지금 형태인지 실제 코드를 근거로 설명한다.

- 기준: 2026/11/08 `develop` 기반 코드. Java 17, Spring Boot 3.5.11, Spring Data JPA, Spring Kafka, Spring Security, WebSocket/STOMP.
- 소스 경로: [`backend/src/main/java/com/example/security_log_system/`](../../backend/src/main/java/com/example/security_log_system/). 아래에서는 이 경로 안의 패키지·클래스 이름만 적는다.
- 관련 문서: [02_architecture.md](02_architecture.md), [03_event_pipeline.md](03_event_pipeline.md), [04_detection.md](04_detection.md), [05_waf_sync.md](05_waf_sync.md), [07_database.md](07_database.md), [08_security.md](08_security.md).

## 1. 패키지 구조

| 패키지 | 클래스 수 | 역할 | 대표 클래스 |
| --- | --- | --- | --- |
| `config` | 13 | 보안 필터 체인, Kafka Consumer·Producer·오류 처리, WebSocket, 스케줄러 실행기, 시계 | `SecurityConfig`, `WafSyncSecurityConfig`, `WafSyncTokenFilter`, `PipelineKafkaErrorConfig`, `OutboxSchedulingConfig` |
| `controller` | 7 | REST 진입점. 검증한 DTO를 서비스에 넘기고 응답 DTO 반환 | `LogController`, `ThreatController`, `BlacklistController`, `AuthController`, `WafSyncController` |
| `kafka` | 4 | Kafka 수신·송신. 파싱·검증 후 서비스 호출 | `LogKafkaConsumer`, `AiResultConsumer`, `WafDetectionConsumer`, `AiRequestProducer` |
| `service` | 24 | 업무 로직·트랜잭션 경계, 요청 상관관계·자동 차단 정책, outbox·알림 발행 | `LogService`, `ThreatService`, `WafDetectionWriter`, `RequestCorrelationService`, `RequestAlertService` |
| `repository` | 11 | JPA 저장소·Specification, JdbcTemplate 저장소 | `LogRepository`, `ThreatRepository`, `AiRequestOutboxRepository`, `RequestAlertRepository` |
| `entity` | 6 | JPA 엔티티 | `LogEntry`, `DetectedThreat`, `WafDetection`, `IpBlacklist`, `AdminUser`, `WafSyncStatus` |
| `dto` | 22 | 요청·응답·Kafka 메시지, 검색 조건 | `LogSearchCondition`, `GroupedThreatResponseDto`, `WafDetectionEventDto`, `RequestAlertMessage` |
| `security` | 5 | 관리자 계정 조회, 운영 초기 관리자, WebSocket·HTTP 세션 연동 | `AdminUserDetailsService`, `ProdAdminInitializer`, `SessionWebSocketHandshakeInterceptor` |
| `exception` | 4 | 입력 오류와 재시도 가능 오류 구분, HTTP 검증 오류 응답 | `InvalidAiResultException`, `InvalidWafEventException`, `AiLogNotReadyException`, `GlobalExceptionHandler` |
| `scheduler` | 1 | 매분 누적 위협 건수 출력(코드 주석상 테스트용) | `ReportScheduler` |
| `util` · `validation` | 1 · 2 | UTC 시간 변환, IP 형식 검증 어노테이션 | `UtcDateTime`, `ValidIpAddress` |

`WebConfig`의 `RestTemplate` 빈은 현재 참조하는 코드가 없다. 기본 AI 분석은 Kafka 비동기 경로만 사용한다.

## 2. 계층 규칙

| 계층 | 규칙 | 코드 근거 |
| --- | --- | --- |
| 컨트롤러 | `@Valid`로 DTO를 검증하고 서비스를 호출한 뒤 DTO를 반환한다. 엔티티를 응답으로 노출하지 않는다 | `LogResponseDto.from`, `BlacklistResponseDto.from` |
| Kafka Consumer | 엄격 파싱(`FAIL_ON_TRAILING_TOKENS`)과 필수값 검증만 하고 서비스에 위임한다. 업무 예외를 삼키지 않고 컨테이너 오류 처리기로 전파한다 | `AiResultConsumer`, `WafDetectionConsumer` |
| 서비스 | 트랜잭션 경계, 잠금, 중복 재확인, 정책 판단을 둔다 | `LogService`, `ThreatService`, `WafDetectionWriter` |
| 저장소 | 일반 조회·저장은 JPA, 행 잠금·조건부 상태 전이 SQL이 핵심인 테이블은 JdbcTemplate | `AiRequestOutboxRepository`, `RequestAlertRepository` |
| 주입 | 생성자 주입(`@RequiredArgsConstructor` 또는 명시 생성자). `main`에 `@Autowired` 필드 주입이 없다 | 전체 |
| 검증 오류 | `MethodArgumentNotValidException`·`HandlerMethodValidationException`을 필드별 400 응답으로 변환 | `GlobalExceptionHandler`, `ErrorResponseDto` |

토픽·그룹 ID·재시도·DLT를 바꾸면 8절과 [03_event_pipeline.md](03_event_pipeline.md)를 함께 고친다.

## 3. 트랜잭션 경계

같은 요청의 HTTP 로그·WAF 이벤트·AI 결과는 서로 다른 Consumer에서 순서 없이 도착한다. 그래서 **요청별 잠금 → 중복 재확인 → 저장 → 알림 대기 기록 → 자동 차단 평가**를 하나의 트랜잭션에 묶는다.

| 메서드 | 전파·격리 | 트랜잭션 안에서 하는 일 |
| --- | --- | --- |
| `LogService.processRawLog` | REQUIRED, READ_COMMITTED | 요청 잠금, `network_logs` 저장, 먼저 저장된 WAF 탐지 연결, `ai_request_outbox` 등록 |
| `ThreatService.saveAiDetectedThreat` | REQUIRED, READ_COMMITTED | 요청 잠금, AI 탐지 중복 확인, `detected_threats` 저장, 알림 기록, 자동 차단 평가 |
| `WafDetectionWriter.saveNewDetection` | REQUIRED, READ_COMMITTED | 요청 잠금, 중복 재확인, 위협·`waf_detections` 저장(`saveAndFlush`), 알림 기록, 자동 차단 평가 |
| `WafDetectionService.handle` | 트랜잭션 없음 | Writer가 UNIQUE 위반으로 롤백된 뒤 실제 저장 여부를 다시 조회해 동시 중복만 무시 |
| `RequestCorrelationService`, `AutoBlacklistPolicyService`, `RequestAlertService` | 클래스 전체 `MANDATORY` | 호출자 트랜잭션이 없으면 예외. 잠금·저장·정책 평가가 분리되지 않게 강제 |
| `AiRequestOutboxService.enqueue` | `MANDATORY` | 로그 저장과 같은 트랜잭션에서 outbox 행 등록 |
| `AiRequestOutboxService.claimNext` · `markSent` · `retry` | `REQUIRES_NEW`(선점은 READ_COMMITTED) | 선점·완료·재시도 예약을 각각 짧게 커밋. Kafka를 기다리는 동안 DB 트랜잭션을 잡지 않음 |
| `RequestAlertPublisher.publish` | REQUIRED | 알림 행 `FOR UPDATE` → WebSocket 전송 → `markPublished` |

- **요청별 잠금**: `request_correlations`에 `INSERT ... ON DUPLICATE KEY UPDATE`를 실행해 요청 ID 행 잠금을 얻는다. `request_id`가 없는 과거 로그는 `network_logs` 행을 `SELECT ... FOR UPDATE`로 잠근다.
- **UNIQUE 제약**: `uk_network_logs_request_id`, `uk_waf_detections_request_id`, `uk_waf_detections_threat_id`가 잠금 누락에 대한 마지막 방어선이다. AI 결과 재처리는 `existsByLogEntry_IdAndThreatType`로 걸러낸다.
- **알림 대기 정보 동시 저장**: 탐지 저장과 `request_alerts`의 `revision` 증가·`pending=TRUE`를 같은 트랜잭션에 기록한다. 커밋 전에는 전송하지 않으므로 롤백된 탐지의 팝업이 생기지 않는다.
- **전달 한계**: 전송 성공 뒤 `markPublished` 전에 실패하면 같은 revision이 다시 전송될 수 있다. WebSocket 전달은 종단 간 exactly-once가 아니다.
- 자동 차단 조건(같은 요청에서 WAF·AI 모두 탐지, IP 일치, 먼저 저장된 위협이 원인)은 [04_detection.md](04_detection.md)에서 다룬다.

## 4. 인증·인가

필터 체인을 경로로 나눈다. 내부 API는 관리자 세션을 받지 않고, 관리자 API는 내부 토큰을 받지 않는다.

| 항목 | 관리자 체인 [`SecurityConfig`](../../backend/src/main/java/com/example/security_log_system/config/SecurityConfig.java) | 내부 체인 [`WafSyncSecurityConfig`](../../backend/src/main/java/com/example/security_log_system/config/WafSyncSecurityConfig.java) (`@Order(1)`) |
| --- | --- | --- |
| 대상 | `/internal/waf/**`를 제외한 전체 | `securityMatcher("/internal/waf/**")` |
| 인증 | HTTP 세션(`HttpSessionSecurityContextRepository`, `requireExplicitSave(true)`) | [`WafSyncTokenFilter`](../../backend/src/main/java/com/example/security_log_system/config/WafSyncTokenFilter.java)가 `X-WAF-Sync-Token` 검증. STATELESS, `NullSecurityContextRepository` |
| 허용 | `GET /api/v1/auth/csrf`, `GET /actuator/health`, `POST /api/v1/auth/login`만 공개. 나머지 `hasRole("ADMIN")` | `GET /internal/waf/blacklist`(`WAF_BLACKLIST_READ`), `POST /internal/waf/sync-status`(`WAF_SYNC_STATUS_WRITE`). 그 외 `denyAll` |
| CSRF | `HttpSessionCsrfTokenRepository`. HTTP 단계 예외는 SockJS 전송 경로 `/ws-security/**`뿐 | 예외는 `/internal/waf/sync-status`뿐 |
| 실패 응답 | 미인증 401, 권한 부족·CSRF 실패 403 | 토큰 누락·불일치 401, 권한 403 |

- 토큰 필터: 설정 토큰이 32자 미만이면 기동 실패, 비어 있으면 모든 내부 요청이 401이다. 비교는 `MessageDigest.isEqual`(상수 시간)이다.
- 로그인: `AuthService.loginWithSession`이 인증 후 `ChangeSessionIdAuthenticationStrategy`(세션 고정 방지)와 `CsrfAuthenticationStrategy`(로그인 전 CSRF 토큰 폐기)를 적용하고 세션에 명시 저장한다. 비밀번호는 `BCryptPasswordEncoder`로 검증한다.
- 로그인 실패 제한(2026/11/08): [`LoginAttemptLimiter`](../../backend/src/main/java/com/example/security_log_system/service/LoginAttemptLimiter.java)가 사용자 이름별로 실패를 센다.
  - 기본값: 15분 안에 5번 실패하면 15분 동안 잠근다. 잠긴 동안은 비밀번호를 검사하지 않고 `429 Too Many Requests`와 `Retry-After`(초)를 돌려준다. 성공하면 기록을 지운다.
  - 사용자 이름은 대소문자·앞뒤 공백을 구분하지 않는다. 클라이언트 IP는 기준으로 쓰지 않는다(프록시 뒤라 원격 주소가 사용자 IP가 아니고, 임의의 `X-Forwarded-For`를 신뢰하지 않음).
  - 백엔드 1개의 메모리에 두므로 재시작하면 초기화된다. 사용자 이름 기준이라 공격자가 계정을 일시적으로 잠글 수는 있다(잠금은 자동 해제).
- 로그아웃: `POST /api/v1/auth/logout` → 세션 무효화, `JSESSIONID` 삭제, 204. 폼 로그인·HTTP Basic은 끈다.
- 쿠키·세션: `JSESSIONID`, HttpOnly, SameSite=Lax, Secure(`SESSION_COOKIE_SECURE`, 기본 true, local 프로필 false), 비활성 만료 30분. `spring-session` 의존성이 없어 세션은 서블릿 메모리에 있고 재시작하면 로그아웃된다.
- 초기 관리자: local 프로필 `LocalAdminInitializer`, prod 프로필 `ProdAdminInitializer`(`app.bootstrap-admin.enabled=true`이고 `ROLE_ADMIN`이 없을 때만, 비밀번호 8자 이상·UTF-8 72바이트 이하). `POST /api/v1/auth/register`도 관리자만 호출한다.
- CORS: `app.cors.allowed-origins`만 허용하고 `allowCredentials=true`. 프론트는 `frontend/src/api/apiClient.js`가 `/api/v1/auth/csrf`로 받은 토큰을 변경 요청 헤더에 넣는다.

## 5. 시간 규칙

| 위치 | 규칙 | 코드 |
| --- | --- | --- |
| DB 저장(JPA) | 시간대 없는 `LocalDateTime`을 UTC 기준으로 다룬다. DB 원문은 드라이버 변환 때문에 KST처럼 보인다(EC2 확인, [07 데이터베이스](07_database.md) 7절) | `UtcDateTime.now()` = `LocalDateTime.now(ZoneOffset.UTC)` |
| DB 저장(JdbcTemplate) | DB 함수 `UTC_TIMESTAMP(6)` | `AiRequestOutboxRepository`, `RequestAlertRepository` |
| WAF 보고 수신 시각 | `Clock.systemUTC()` 빈 | `WafSyncTimeConfig`, `WafSyncStatusService` |
| WAF 이벤트 발생 시각 | 원문은 `event_time_raw`에 보존하고 `app.kafka.waf.event-zone`으로 해석해 UTC 변환. 실패하면 현재 시각으로 대체하지 않고 NULL | `WafDetectionWriter.parseOccurredAt` |
| API 응답 | UTC 오프셋이 붙은 `OffsetDateTime` | `UtcDateTime.toOffset`, `LogResponseDto`, `ThreatResponseDto` |
| 화면 | `Asia/Seoul`로 표시 | `frontend/src/utils/dateTime.js` |

수동으로 9시간을 더하거나 전역 시간대를 바꾸지 않는다. 남아 있는 예외는 다음과 같다.

- 테스트 입력 형식(`{"log": ...}` Nginx 문자열, dev_tools JSON), AI 요청 DTO의 `timestamp`, `GlobalExceptionHandler` 응답 시각은 `LocalDateTime.now()`(JVM 기본 시간대)를 쓴다. 실제 WAF access JSON 경로는 `UtcDateTime.now()`다.
- JDBC URL에 `serverTimezone=Asia/Seoul`이 있다. 2026/11/01 로컬 r08 진단에서는 JPA로 저장된 DATETIME을 +09:00으로 해석해야 관측 순서와 맞았다([server-observation.md](../testing/local/server-observation.md)). JDBC 바인딩·EC2 데이터의 실제 저장 의미는 (미확인)이며, 측정 도구는 저장 기준을 실행 인자로 명시한다.

## 6. WebSocket/STOMP

| 구성 | 내용 | 코드 |
| --- | --- | --- |
| 엔드포인트 | `/ws-security`(SockJS). 허용 Origin은 `app.cors.allowed-origins` | `WebSocketConfig` |
| 브로커 | 단순 브로커 `/topic`, 애플리케이션 접두사 `/app` | `WebSocketConfig` |
| 핸드셰이크 | 인증된 principal과 기존 HTTP 세션이 있어야 연결. 새 세션을 만들지 않음 | `SessionWebSocketHandshakeInterceptor` |
| 세션 연동 | HTTP 세션이 만료·로그아웃되면 그 세션의 WebSocket을 종료 코드 1008로 모두 닫음 | `SessionWebSocketConnections`, `SessionWebSocketHandlerDecorator` |
| 메시지 권한 | CONNECT, `/topic/threats` 구독, HEARTBEAT·UNSUBSCRIBE·DISCONNECT만 ADMIN 허용. 나머지(클라이언트 발행 포함) `denyAll` | `WebSocketSecurityConfig`(`@EnableWebSocketSecurity`) |
| CSRF | 프론트가 연결 전 `/api/v1/auth/me`·`/api/v1/auth/csrf`를 조회하고 토큰을 STOMP CONNECT 헤더에 넣는다 | `frontend/src/hooks/useWebSocket.js` |
| 알림 메시지 | `/topic/threats`로 `RequestAlertMessage`(alertId, CREATED/UPDATED, revision, clientIp, type, level, time, sources) | `RequestAlertPublisher` |

`NotificationService.sendUrgentAlert`(`@Async`)는 HTTP 보조 API `POST /api/v1/threats/detect`에서 위험도 4 이상일 때만 쓰는 수동 테스트 경로다. 커밋 후 전송을 보장하지 않는다.

## 7. 스케줄러·발행기

`WebConfig`가 `@EnableScheduling`·`@EnableAsync`를 켜고, `OutboxSchedulingConfig`가 실행기를 둘로 나눈다. Kafka 전송 대기가 알림 전송을 막지 않게 하기 위해서다.

| 실행기(스레드 수) | 작업 | 주기 설정 키(코드 기본값) | 켜기·끄기 키 |
| --- | --- | --- | --- |
| `taskScheduler`(1) | `RequestAlertDispatcher.dispatch`: `pending=TRUE` 최대 100건 발행 | `app.alerts.poll-delay-ms`(1000), `app.alerts.initial-delay-ms`(5000) | `app.alerts.enabled`(true) |
| `taskScheduler`(1) | `RequestAlertWakeup`: 알림 기록 커밋 직후 발행 1회 예약 | - | `app.alerts.wakeup-enabled`(true) |
| `taskScheduler`(1) | `ReportScheduler.generateReport`: 위협 건수 출력 | cron `0 * * * * *` | 없음 |
| `aiRequestOutboxScheduler`(1) | `AiRequestOutboxDispatcher.dispatch`: 한 주기 최대 20건 발행 | `app.ai-outbox.poll-delay-ms`(500), `app.ai-outbox.initial-delay-ms`(5000) | `app.ai-outbox.enabled`(true) |
| `aiRequestOutboxScheduler`(1) | `AiRequestOutboxWakeup`: 로그 저장 커밋 직후 발행 1회 예약 | - | `app.ai-outbox.wakeup-enabled`(true) |

- **커밋 후 깨우기**(`AfterCommitDispatchTrigger`): `afterCommit`에서만 예약하고 롤백이면 예약하지 않는다. 발행기와 같은 단일 스레드 실행기에 넣어 주기 실행과 겹치지 않으며, 시작 전 예약이 있으면 추가하지 않는다. 예약 실패는 예외 없이 주기 조회로 복구한다. 근거와 측정은 [트러블슈팅_5](<../testing/ec2/트러블슈팅_5(상세본).md>).
- **AI outbox 상태 전이**: `PENDING` → 선점(`FOR UPDATE SKIP LOCKED`, `IN_FLIGHT`, `lease_token`, 60초 임대, `attempts+1`) → Kafka 응답 최대 20초 대기 → `SENT`. 실패하면 `min(attempts, 12) × 5`초 뒤 `PENDING`으로 돌린다. 임대가 끝난 `IN_FLIGHT`는 다시 선점된다. 완료 기록에 실패하면 재발행될 수 있으므로 AI 결과 저장의 중복 확인이 함께 필요하다.
- **알림 발행**: 행 잠금 → 전송 → `revision`이 그대로일 때만 `published_revision` 갱신·`pending=FALSE`. 실패는 경고 로그 후 다음 주기에 재시도한다.
- 운영 주기 250ms의 근거: [트러블슈팅_1](<../testing/ec2/트러블슈팅_1(상세본).md>)(알림), [트러블슈팅_2](<../testing/ec2/트러블슈팅_2(상세본).md>)(AI outbox).

## 8. 오류 처리

| 토픽(그룹) | 컨테이너 팩토리 | 재시도 | 재시도하지 않는 예외 | DLT |
| --- | --- | --- | --- | --- |
| `log-topic`(`log-group`) | `kafkaListenerContainerFactory` | `FixedBackOff(1000ms, 2회)` | `InvalidAiResultException`, `JsonProcessingException` | `log-topic.DLT`(보관 7일) |
| `ai-result-topic`(`ai-result-group`) | `kafkaListenerContainerFactory` | 같음 | 같음 | `ai-result-topic.DLT`(보관 7일) |
| `waf-detection-topic`(`waf-detection-group`) | `wafKafkaListenerContainerFactory` | 같음 | `InvalidWafEventException` | `waf-detection-topic.DLT` |

- 세 경로 모두 자동 커밋을 끄고 `AckMode.RECORD`를 쓴다. DLT 전송 실패는 복구 성공으로 처리하지 않는다(`setFailIfSendResultIsError(true)`). 이때 원본 offset은 전진하지 않는다.
- `InvalidAiResultException`: AI 결과가 비었거나 JSON·`logId`·`threatScore`(0~1 유한값)·`ipAddress`가 잘못된 경우다. 같은 메시지를 다시 처리해도 해결되지 않으므로 바로 DLT로 보낸다.
- `AiLogNotReadyException`: AI 결과가 로그 커밋보다 먼저 보인 경우다. 재시도 대상이다.
- 오류 로그에는 원문 대신 topic·partition·offset·시도 횟수·예외 이름만 남긴다. AI 장애나 잘못된 메시지를 정상 결과로 바꾸지 않는다.
- WAF Consumer와 전용 팩토리는 `app.kafka.waf.enabled=true`일 때만 생성된다.
- DLT 재처리 도구는 `scripts/testing/kafka_replay.py`, 장애 복구 검증 기록은 [recovery-verification.md](../testing/local/recovery-verification.md)에 있다.

## 9. 주요 설정 키

값은 이름과 기본값만 적는다. 운영 실제 값은 EC2 `.env.aws`에 있으며 문서로 옮기지 않는다.

| 설정 키 | 환경 변수 | 기본값 | compose.aws.yaml 전달값·비고 |
| --- | --- | --- | --- |
| `spring.jpa.hibernate.ddl-auto` | - | `validate` | 스키마 검사만. [07_database.md](07_database.md) |
| `spring.datasource.url` · `username` · `password` | `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` | local: localhost MySQL(`serverTimezone=Asia/Seoul`), prod: 필수 | URL은 서비스명 `db` 고정, 계정은 필수(`:?`) |
| `spring.kafka.bootstrap-servers` | `KAFKA_BOOTSTRAP_SERVERS` | local `localhost:9092`, prod 필수 | `kafka:29092` |
| `app.cors.allowed-origins` | `CORS_ALLOWED_ORIGINS` | local `http://localhost:3000`, prod 필수 | 필수 |
| `app.bootstrap-admin.*` | `APP_BOOTSTRAP_ADMIN_ENABLED` · `_USERNAME` · `_PASSWORD` | false, 빈 값 | 기본 false |
| `app.auth.login-limit.max-failures` · `window-seconds` · `lock-seconds` | `APP_AUTH_LOGINLIMIT_MAXFAILURES` · `_WINDOWSECONDS` · `_LOCKSECONDS` | 5, 900, 900 | 전달하지 않음(기본값) |
| `app.kafka.waf.enabled` · `event-zone` | `WAF_CONSUMER_ENABLED`, `WAF_EVENT_ZONE` | false, `UTC` | 같음 |
| `app.waf-sync.token` | `WAF_SYNC_TOKEN` | 빈 값(내부 API 전부 401) | WAF와 같은 값 |
| `app.waf-sync.expected-waf-id` · `stale-after-seconds` | `WAF_ID`, `WAF_SYNC_STALE_AFTER_SECONDS` | `local-waf-1`, 60 | `aws-waf-1`, 60 |
| `app.testing.trace-enabled` | `PIPELINE_TRACE_ENABLED` | false | `DG_TRACE` 측정 로그 |
| `app.ai-outbox.enabled` · `poll-delay-ms` · `wakeup-enabled` | `AI_OUTBOX_ENABLED`, `APP_AIOUTBOX_POLLDELAYMS`, `APP_AIOUTBOX_WAKEUPENABLED` | true, 500, true | true, 250, true |
| `app.alerts.poll-delay-ms` · `wakeup-enabled` | `APP_ALERTS_POLLDELAYMS`, `APP_ALERTS_WAKEUPENABLED` | 1000, true(코드 기본값) | 250, true |
| `server.servlet.session.cookie.secure` | `SESSION_COOKIE_SECURE` | true(local false) | `"true"` |
| `server.forward-headers-strategy` | `SERVER_FORWARD_HEADERS_STRATEGY` | 미설정 | `native`(앞단 HTTPS 인식) |
| `server.port` | `SERVER_PORT` | 8080 | 호스트 `127.0.0.1:8080` 바인딩 |

- `app.alerts.*`는 `application*.yml`에 없고 코드 기본값과 Compose 환경 변수(완화 바인딩)로만 정해진다.
- `ai_request_outbox` 등록은 `AI_OUTBOX_ENABLED`와 무관하게 항상 일어난다. 이 값은 발행기 생성 여부만 정한다.
- `spring.flyway.*` 설정은 있지만 Flyway 의존성과 `db/migration` 디렉터리가 없어 동작하지 않는다.
- `application-local.yml`·`application-prod.yml`의 `management` 블록은 원래 `spring:` 아래에 들어가 있어 적용되지 않았다. 2026/11/08에 최상위로 옮겼다.
  - prod: 공통 설정과 같은 `health`(상세 `never`)만 노출해 동작 변화가 없다.
  - local: `health`·`info`·`metrics`·`prometheus`를 노출한다. `health` 외 경로는 `SecurityConfig`가 관리자 로그인을 요구한다.

## 10. 테스트 구성

`backend/src/test/java/com/example/security_log_system/` 기준이다. 대부분 Mockito 단위 테스트이고 실제 DB가 필요한 테스트는 두 개다. 실행 명령은 AGENTS.md의 검증 표를 따른다.

| 묶음 | 테스트 클래스 | 확인하는 것 |
| --- | --- | --- |
| 보안·컨트롤러 | `WafSyncControllerTest`(`@WebMvcTest` + 실제 두 보안 설정), `AuthControllerTest`, `BlacklistControllerTest`, `LogControllerTest`, `ThreatControllerTest` | 토큰 누락·불일치 401, 관리자 세션으로 내부 API 불가, 토큰으로 관리자 API 불가, 관리자 삭제의 CSRF 요구, 입력 검증 400 |
| Consumer·Kafka 설정 | `AiResultConsumerTest`, `LogConsumerTest`, `WafDetectionConsumerTest`, `PipelineKafkaErrorConfigTest`, `AiRequestTopicConfigTest` | 잘못된 입력·뒤붙은 JSON 거부, 서비스 예외 전파, DLT 전송 실패 전파 |
| 저장·상관관계·정책 | `LogServiceTest`, `ThreatServiceTest`, `WafDetectionServiceTest`, `WafDetectionWriterTest`, `AutoBlacklistPolicyServiceTest` | 도착 순서 역전, AI 결과 중복 무시, 동시 중복 무시, 발생 시각 보존·UTC 변환, IP 불일치 시 자동 등록 생략 |
| outbox·알림·깨우기 | `AiRequestOutboxPublisherTest`, `AfterCommitDispatchTriggerTest`, `AfterCommitWakeupHookTest`, `AfterCommitWakeupWiringTest`, `PipelineTraceTest` | ACK 후 완료·실패 시 재시도 예약, 커밋 후에만 예약, 변경이 없으면 깨우지 않음 |
| 블랙리스트·조회·검증 | `BlacklistServiceTest`, `BlacklistSnapshotServiceTest`, `WafDetectionQueryServiceTest`, `AuthServiceTest`, `WafDetectionEventDtoTest`, `IpAddressValidatorTest` | 중복 IP 등록 거부, 스냅샷 version, WAF 상세 조회, 필수값·IP 형식 |
| 통합(실제 DB) | `SecurityLogSystemApplicationTests.contextLoads` | 실제 MySQL 스키마에서 `validate` 통과. CI는 스키마 SQL 4개를 먼저 적용 |
| 복구 검증 | `RecoveryVerificationTest` | `DG_RECOVERY_DB_URL`이 전용 `dg_recovery_*` 스키마일 때만 실행. 임베디드 Kafka(KRaft)로 롤백 원자성, Kafka 장애 후 재전송, JVM 종료 후 복구, DLT 실패 시 offset 미전진 |

`backend/src/test/k6/`는 JUnit이 아닌 k6 부하 스크립트다.

## 결정 · 대안 · 근거

| 결정 | 검토한 대안 | 선택 근거 | 관련 문서·코드 |
| --- | --- | --- | --- |
| 관리자 인증은 HTTP 세션 + CSRF | JWT(헤더 또는 저장소 보관) | 단일 대시보드·동일 출처 구조에서 HttpOnly 쿠키로 토큰을 스크립트에 노출하지 않고, 로그아웃·세션 종료 시 WebSocket까지 즉시 끊을 수 있다. 백엔드 코드에 JWT 구현은 없다(CI의 `JWT_SECRET` 변수는 코드에서 읽지 않음) | `SecurityConfig`, `SessionWebSocketConnections` |
| 내부 API는 별도 필터 체인과 전용 토큰 | 관리자 세션 재사용, IP 허용 목록 | WAF 스크립트는 로그인·CSRF 흐름을 가질 수 없고, 권한을 조회·보고 두 경로로 한정해야 한다. 세션과 섞이지 않게 STATELESS 체인으로 분리 | `WafSyncSecurityConfig`, `WafSyncTokenFilter`, [05_waf_sync.md](05_waf_sync.md) |
| 상관관계·정책·알림 서비스는 `MANDATORY` | 각 서비스가 자체 트랜잭션 시작 | 잠금·저장·정책 평가·알림 대기 기록이 한 커밋으로 묶여야 순서 역전과 재처리에서도 중복·누락이 없다. 잘못 호출하면 즉시 예외가 난다 | `RequestCorrelationService`, `AutoBlacklistPolicyService`, `RequestAlertService` |
| AI 요청은 transactional outbox + 커밋 후 깨우기 | 저장 직후 Kafka 직접 전송, 주기 조회만 사용 | 로그 저장과 요청 발행의 원자성을 지키면서(로컬 r15 정합성 문제 보완), 주기 조회 대기만큼의 지연을 줄인다. 주기 조회는 복구 경로로 유지 | `AiRequestOutboxService`, `AfterCommitDispatchTrigger`, [트러블슈팅_5](<../testing/ec2/트러블슈팅_5(상세본).md>) |
| 입력 오류는 바로 DLT, 저장 오류는 2회 재시도 후 DLT | 모든 예외 무한 재시도, 실패 메시지 버림 | 고칠 수 없는 메시지가 파티션을 막지 않게 하고, 일시 장애는 복구 기회를 주며, DLT 전송 실패 시 offset을 지켜 유실을 막는다 | `PipelineKafkaErrorConfig`, `WafKafkaConsumerConfig` |
| DB는 UTC `LocalDateTime`, API는 오프셋, 화면은 `Asia/Seoul` | KST 저장, 전역 시간대 변경 | 서버·DB·브라우저 시간대 차이를 한 곳(표시)에서만 변환한다. JDBC `serverTimezone`과의 관계는 남은 확인 과제 | `UtcDateTime`, `frontend/src/utils/dateTime.js` |
