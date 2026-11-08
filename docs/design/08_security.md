# 보안 설계

이 문서는 DualGuard의 위협 모델(보호 자산·행위자·진입점)과 코드·설정으로 구현된 통제 수단, 비밀 관리, 알려진 한계를 정리한다.

- 기준: 2026/11/08. 근거는 코드, `compose.aws.yaml`, `waf/` 설정이다. 보안 그룹·호스트 Nginx 같은 서버 설정은 [../operations/aws_deployment.md](../operations/aws_deployment.md)의 운영 절차 기준이며 실제 콘솔 값은 별도 확인 대상이다.
- 관련 문서: [02_architecture.md](02_architecture.md), [04_detection.md](04_detection.md), [05_waf_sync.md](05_waf_sync.md), [06_backend.md](06_backend.md), [07_database.md](07_database.md).
- 탐지율·오탐률 평가는 이 문서 범위가 아니다. 구현되지 않은 통제는 8절 한계에 적는다.

## 1. 보호 자산

| 자산 | 위치 | 침해 시 영향 |
| --- | --- | --- |
| 관리자 계정·세션 | `admin_users`(BCrypt 해시), 서블릿 세션, `JSESSIONID` 쿠키 | 블랙리스트 조작, 기록 열람 |
| 차단 정책 | `ip_blacklist`, WAF 상태 볼륨 `waf-blacklist-state` | 정상 사용자 차단 또는 공격자 차단 해제 |
| 탐지·로그 기록 | `network_logs`(`raw_log`에 요청 본문 포함), `detected_threats`, `waf_detections` | 사고 분석 근거 훼손, 요청 본문 속 개인정보 노출 |
| 내부 동기화 토큰 | `WAF_SYNC_TOKEN`(backend·WAF 공유) | 차단 목록 조회, 적용 상태 보고 위조 |
| 비밀 설정 | `.env`, EC2 `.env.aws` | DB·전체 서비스 권한 |
| 보호 대상 서비스 | JuiceShop(의도적으로 취약한 시험 대상) | 공격 트래픽의 목적지 |

## 2. 행위자

| 행위자 | 접근 경로 | 신뢰 수준 |
| --- | --- | --- |
| 외부 사용자·공격자 | 공개 HTTPS → WAF → JuiceShop | 신뢰하지 않음 |
| 관리자 | HTTPS 대시보드 → 프론트 Nginx → backend | 로그인 후 `ROLE_ADMIN` |
| WAF 동기화 프로세스 | WAF 컨테이너의 `blacklist-sync.sh` → backend `/internal/waf/**` | 공유 토큰 보유자 |
| 내부 서비스 | Fluent Bit·AI·backend ↔ Kafka·MySQL | Docker 네트워크 격리에 의존. 서비스 간 인증 없음 |
| 운영자 | SSH·SSM, GitHub Actions 배포 | 서버 전체 권한 |

## 3. 진입점과 노출 범위

```text
[인터넷] ─443→ 호스트 Nginx (TLS 종료, X-Forwarded-For 덮어쓰기)
                 ├→ 127.0.0.1:8081 WAF ──→ juiceshop:3000 (expose만)
                 └→ 127.0.0.1:3000 프론트 Nginx ──→ /api/, /ws-security ──→ backend:8080
[Docker 네트워크]  WAF ──→ backend:8080 /internal/waf/** (X-WAF-Sync-Token)
                  Fluent Bit·backend·AI ──→ kafka:29092 (PLAINTEXT), backend ──→ db:3306
```

| 진입점 | `compose.aws.yaml` 노출 | 인증 | 비고 |
| --- | --- | --- | --- |
| WAF | `127.0.0.1:8081` | 없음(공개 서비스 앞단) | 외부 요청은 호스트 Nginx를 거쳐서만 도달 |
| 프론트 | `127.0.0.1:3000` | 화면은 공개, API는 세션 | [`frontend/nginx.conf`](../../frontend/nginx.conf)는 `/api/`, `/ws-security`, 정적 파일만 전달한다. `/internal/**`, `/actuator/**`는 외부 HTTPS로 도달하지 않는다 |
| backend | `127.0.0.1:8080` | 세션 + CSRF, 내부 API는 토큰 | [06_backend.md](06_backend.md) 4절 |
| AI | `127.0.0.1:8000` | 없음(`/predict` 등 HTTP API 무인증) | 루프백·Docker 네트워크 한정 |
| MySQL·Kafka·Zookeeper | 포트 공개 없음 | DB 계정 / Kafka 인증 없음 | Docker 네트워크 내부 전용 |
| JuiceShop | `expose: 3000`만 | - | WAF만 접근 |
| SSH 22 | 보안 그룹(관리자 공인 IP) | 키 | 운영 문서 기준 |

로컬 `compose.yaml`도 DB(3306)·Kafka(9092)·backend·프론트·AI·WAF 포트를 모두 `127.0.0.1`에 바인딩한다.

## 4. 통제 수단

### 4-1. 공개 트래픽(WAF)

- **탐지와 차단의 분리**: `MODSEC_RULE_ENGINE=DetectionOnly`라 CRS·커스텀 규칙은 탐지·기록만 한다. 실제 차단은 블랙리스트 IP의 403뿐이다. 동기화 규칙(id 20100, `CUSTOM-003`)과 수동 규칙(id 20001~20099, `CUSTOM-002`)이 `ctl:ruleEngine=On`으로 해당 요청만 차단한다. Spring 백엔드는 JuiceShop 요청을 받는 차단 계층이 아니다.
- **기록·자동 차단 정책**: WAF 또는 AI 탐지 시 기록·통합 알림, 같은 요청에서 둘 다 탐지되고 IP가 일치하면 자동 블랙리스트 등록([04_detection.md](04_detection.md)).
- **실패 시 기존 차단 유지**: 조회·JSON 검증·파일 교체·reload 실패 시 마지막 정상 룰을 유지·복구하고, 정상 응답의 빈 목록만 차단 해제로 본다([05_waf_sync.md](05_waf_sync.md)).
- **차단 제외 IP**: `0.0.0.0`·`::`, 루프백, 컨테이너 기본 게이트웨이, 단일 IP인 `SET_REAL_IP_FROM`, `WAF_SYNC_EXCLUDE_IPS`, 지원하지 않는 형식은 등록돼도 차단하지 않고 제외 사유를 보고한다([waf/README.md](../../waf/README.md#블랙리스트-자동-동기화)).

### 4-2. 실제 클라이언트 IP 신뢰

- 호스트 Nginx가 `proxy_set_header X-Forwarded-For $remote_addr`로 클라이언트가 보낸 값을 덮어쓴다(운영 문서 절차).
- WAF는 `SET_REAL_IP_FROM=${WAF_TRUSTED_PROXY}`(Docker 게이트웨이 주소, 누락 시 Compose 실패)에서 온 `X-Forwarded-For`만 실제 IP로 복원한다(`REAL_IP_HEADER: X-Forwarded-For`).
- WAF 포트는 `127.0.0.1:8081`에 바인딩한다. 외부에 직접 열면 `X-Forwarded-For` 위조가 가능하다는 이유가 `compose.aws.yaml` 주석에 있다.
- WAF는 `X-Request-ID`·`X-DualGuard-Request-Start` 응답 헤더를 자체 생성 값으로 덮어쓴다. 실험 표식 헤더(`X-DualGuard-Test-*`)는 관측 필터일 뿐 인증·IP 신뢰·차단 근거로 쓰지 않는다.
- backend는 `SERVER_FORWARD_HEADERS_STRATEGY=native`로 앞단 HTTPS를 인식해 Secure 쿠키를 쓴다. backend 포트도 루프백 바인딩이다.

### 4-3. 관리자 API·대시보드

| 위협 | 통제 | 위치 |
| --- | --- | --- |
| 무단 API 호출 | 공개 3개 경로(CSRF 조회, health, 로그인) 외 전부 `hasRole("ADMIN")`. 미인증 401, 권한 부족 403 | `SecurityConfig` |
| CSRF | `HttpSessionCsrfTokenRepository`. 예외는 SockJS 전송 `/ws-security/**`와 내부 보고 `/internal/waf/sync-status`뿐. STOMP CONNECT에도 토큰을 넣는다 | `SecurityConfig`, `useWebSocket.js` |
| 세션 고정·탈취 | 로그인 시 세션 ID 변경, 로그인 전 CSRF 토큰 폐기. 쿠키 HttpOnly·SameSite=Lax·Secure(운영), 비활성 만료 30분 | `AuthService`, `application.yml` |
| 비밀번호 무차별 대입 | 사용자 이름별로 15분 안에 5번 실패하면 15분 동안 비밀번호 검사 없이 429·`Retry-After`로 거절(2026/11/08) | `LoginAttemptLimiter`, `AuthService`, `AuthController` |
| 비밀번호 유출 | BCrypt 저장. 운영 초기 관리자는 관리자가 없을 때만 생성, 8자 이상·72바이트 이하, 비밀번호·해시 로그 미출력 | `ProdAdminInitializer` |
| 교차 출처 요청 | CORS는 `CORS_ALLOWED_ORIGINS`만 허용(자격 증명 포함) | `SecurityConfig`, `WebSocketConfig` |
| 실시간 알림 무단 구독 | 핸드셰이크에 인증 principal·기존 세션 필요, CONNECT·`/topic/threats` 구독만 ADMIN 허용, 클라이언트 발행 차단, 세션 종료 시 소켓 종료(1008) | `WebSocketSecurityConfig`, `security/` |
| 운영 정보 노출 | Actuator는 `health`만 노출, 상세 `never`. springdoc(Swagger) 경로도 ADMIN 필요이며 프론트 Nginx가 전달하지 않는다 | `application.yml`, `frontend/nginx.conf` |

### 4-4. 내부 동기화 API

- `/internal/waf/**` 전용 필터 체인이 `X-WAF-Sync-Token`만 인증한다. 토큰은 32자 이상이어야 기동되고, 비어 있으면 모든 내부 요청이 401이다. 비교는 상수 시간(`MessageDigest.isEqual`)이다.
- 허용 경로는 `GET /internal/waf/blacklist`, `POST /internal/waf/sync-status` 두 개이고 나머지는 `denyAll`이다. 관리자 세션으로 내부 API를 호출할 수 없고, 토큰으로 관리자 API를 호출할 수 없다(`WafSyncControllerTest`).
- 보고의 `wafId`가 `app.waf-sync.expected-waf-id`와 다르면 400으로 거부한다. 스냅샷 응답은 `Cache-Control: no-store`다.

### 4-5. 로그·메시지의 민감 정보

- [`waf/njs/headers.js`](../../waf/njs/headers.js)는 access 로그 `headers` 필드에서 `cookie`, `authorization`, `set-cookie`, `proxy-authorization`, `x-api-key` 값을 `***MASKED***`로 바꾼다.
- WAF 탐지 이벤트는 Fluent Bit Lua 필터(`waf/waf-detection.lua`)가 요청·응답 본문, 헤더, 쿼리 문자열을 빼고 규칙 정보와 경로만 보낸다.
- backend 오류 로그는 Kafka 원문 대신 topic·partition·offset·예외 이름만 남긴다. AI·WAF 메시지 파싱 예외에도 원문을 넣지 않는다. outbox `last_error_code`에는 예외 클래스 이름만 저장한다.
- 내부 메시지는 엄격 파싱·필수값 검증을 거치며, 잘못된 메시지는 정상 결과로 바꾸지 않고 DLT로 보낸다([06_backend.md](06_backend.md) 8절).

## 5. 비밀 관리

| 항목 | 규칙 | 근거 |
| --- | --- | --- |
| `.env`, `.env.*` | Git 제외. `.env.example`만 예외로 추적 | `.gitignore` |
| `aws.env.example` | 추적되는 EC2 예제. 비밀번호는 자리표시자, `WAF_SYNC_TOKEN`·초기 관리자 계정 값은 빈 값, 토큰 생성 예(`openssl rand -hex 32`)만 안내 | [`aws.env.example`](../../aws.env.example) |
| EC2 `.env.aws` | 서버에서 직접 관리. `scripts/deploy.sh`는 이미지 접두사·태그만 기록 | `compose.aws.yaml` 주석 |
| 필수 비밀·설정 | `MYSQL_ROOT_PASSWORD`, `DB_USERNAME`, `DB_PASSWORD`, `CORS_ALLOWED_ORIGINS`, `WAF_TRUSTED_PROXY`는 `:?` 문법으로 누락 시 Compose 실패 | `compose.aws.yaml` |
| 백엔드 DB 계정 | 앱 전용 계정 사용. 예제 주석상 root를 앱에 쓰지 않는다 | `aws.env.example` |
| 초기 관리자 | 최초 1회만 `APP_BOOTSTRAP_ADMIN_ENABLED=true`, 생성 후 false로 돌리고 값을 비움 | `aws.env.example`, 운영 문서 |
| AWS 자격 증명 | 배포 워크플로는 OIDC(`id-token: write`)로 임시 자격 증명을 받고 역할 ARN 등은 저장소 변수(`vars.*`)로 둔다. 장기 액세스 키를 쓰지 않는다 | `.github/workflows/deploy.yml` |
| NVD API 키 | 환경 변수 `NVD_API_KEY`로만 읽는다 | `backend/build.gradle` |
| CI DB | 일회용 MySQL 서비스 컨테이너의 테스트 전용 계정 | `.github/workflows/ci.yml` |

문서·보고서에는 비밀값, 토큰, `.env` 내용, 실제 IP를 적지 않고 설정 이름만 쓴다.

## 6. 오픈소스 보안 점검

절차와 결과 확인 방법은 [oss-security-check.md](../security/oss-security-check.md)에 있다.

| 도구 | 설정 | 범위·특성 |
| --- | --- | --- |
| OWASP Dependency-Check(Gradle 플러그인 12.2.2) | `dependencyCheckAnalyze`, HTML·JSON 보고서, `failBuildOnCVSS = 11` | CVSS 최대값이 10이므로 빌드를 실패시키지 않는 보고 전용 설정 |
| CycloneDX(3.2.4) | `cyclonedxDirectBom`(`runtimeClasspath`) | backend SBOM 생성 |
| GitHub CodeQL | `.github/workflows/codeql.yml`, `java-kotlin`, develop·main push·PR | Java 정적 분석 |

세 도구 모두 backend만 대상으로 한다. 프론트(npm), `AI_new`(pip), 컨테이너 이미지(CRS·MySQL·Kafka·JuiceShop)의 취약점 점검은 자동화돼 있지 않다.

## 7. 운영 경계에서 지키는 규칙

- 일반 공격 규칙의 `DetectionOnly`와 블랙리스트 403을 혼동하지 않는다. ‘적용 확인’을 ‘모든 등록 IP 차단 완료’로 표시하지 않는다.
- 실제 IP 신뢰 설정을 완화하거나 임의의 `X-Forwarded-For`를 신뢰하지 않는다. WAF 포트 루프백 바인딩을 유지한다.
- CSRF를 전역으로 끄거나 관리자 API 인증을 풀어 테스트를 통과시키지 않는다.

## 8. 알려진 한계

1. **소급 차단 없음**: AI 분석과 자동 블랙리스트는 이미 JuiceShop에 도달한 요청을 막지 않는다. 등록 전 공격 요청은 `DetectionOnly` 규칙을 그대로 통과한다.
2. **DB 등록과 WAF 적용 사이 지연**: WAF가 다음 동기화(기본 10초)에서 목록을 받아 검증·reload해야 차단된다. 로컬 측정은 등록 후 3초, 삭제 후 7초였다(2026/10/21, waf/README.md). 적용 version 일치, 보고 수신, 실제 403은 서로 다른 확인이며 보고가 60초를 넘으면 상태 미확인이다.
3. **차단 만료 없음**: `ip_blacklist.expired_at`을 설정하지 않고 WAF는 IP만 받는다. 관리자가 삭제해야 해제된다. 차단된 요청도 기록·분석되며 삭제 직후 재등록될 수 있다(waf/README.md 한계).
4. **HTTPS 종료 위치**: TLS는 호스트 Nginx에서 끝난다. 이후 프론트↔backend, WAF↔backend(토큰 포함), backend↔MySQL, Kafka 구간은 단일 호스트 Docker 네트워크 안의 평문 통신이다.
5. **서비스 간 인증 없음**: Kafka 리스너는 PLAINTEXT이고 AI HTTP API는 무인증이다. 같은 Docker 네트워크의 컨테이너가 침해되면 메시지 주입이 가능하며, 포트 비공개와 네트워크 격리에만 의존한다.
6. **요청 본문 저장**: WAF access 로그 형식이 `request_body` 전체를 남겨 `network_logs.raw_log`와 `ai_request_outbox.payload`에 저장된다. 헤더 5종 외의 헤더, 본문, 쿼리 문자열은 마스킹하지 않으며 보존 기간·삭제 정책이 없다. DLT 메시지에도 원문이 남는다(파이프라인 DLT 보관 7일).
7. **로그인 실패 제한은 사용자 이름 기준**(2026/11/08 추가): 15분 안에 5번 실패하면 15분 동안 429로 거절한다([06_backend.md](06_backend.md) 4절). 공격자가 특정 관리자 계정을 일시적으로 잠글 수 있고(자동 해제), 백엔드 메모리에 있어 재시작하면 초기화된다. IP 기준 제한은 프록시 뒤라 하지 않는다.
8. **단일 공유 토큰**: 하나의 정적 토큰이 조회·보고 권한을 모두 가지며 교체 자동화가 없다. backend와 WAF가 같은 값을 써야 하므로 함께 바꿔야 한다.
9. **제외 IP 의존**: 게이트웨이·신뢰 프록시 IP는 차단에서 빠진다. 호스트 Nginx의 `X-Forwarded-For` 덮어쓰기나 `WAF_TRUSTED_PROXY` 설정이 어긋나면 요청이 게이트웨이 IP로 기록돼 차단·자동 등록이 동작하지 않을 수 있다.
10. **세션 메모리 저장**: backend 재시작 시 로그아웃되고, 여러 인스턴스 간 세션 공유를 지원하지 않는다. IPv6는 표기 정규화를 하지 않는다.

## 결정 · 대안 · 근거

| 결정 | 검토한 대안 | 선택 근거 | 관련 문서·코드 |
| --- | --- | --- | --- |
| 일반 규칙은 `DetectionOnly`, 블랙리스트 IP만 403 | CRS 이상 점수 기반 전면 차단 | WAF·AI 탐지를 같은 트래픽에서 비교하기 위해 일반 규칙은 기록만 한다(waf/README.md). 차단은 두 탐지가 겹친 IP와 수동 등록 IP에만 적용 | `compose.aws.yaml`, `waf/README.md`, [04_detection.md](04_detection.md) |
| 관리자 API는 세션 + CSRF | JWT | HttpOnly 쿠키로 토큰을 스크립트에 노출하지 않고, 세션 종료 시 WebSocket까지 즉시 끊는다 | `SecurityConfig`, [06_backend.md](06_backend.md) |
| 내부 API는 전용 토큰 체인 | 관리자 세션 재사용, IP 허용만 | 스크립트가 로그인 흐름을 가질 수 없고 권한을 두 경로로 한정해야 한다. 체인을 나누면 CSRF 예외를 내부 보고 경로 하나로 묶어 둘 수 있다 | `WafSyncSecurityConfig`, `WafSyncTokenFilter` |
| 모든 서비스 포트를 루프백 바인딩, DB·Kafka는 미공개 | 보안 그룹만으로 포트 제한 | 보안 그룹 실수와 무관하게 외부 노출을 막고, WAF 직접 접근에 따른 `X-Forwarded-For` 위조를 차단한다 | `compose.aws.yaml`, [../operations/aws_deployment.md](../operations/aws_deployment.md) |
| 신뢰 프록시 한 곳의 `X-Forwarded-For`만 신뢰 | 모든 `X-Forwarded-For` 신뢰, TCP 상대 IP만 사용 | 차단·자동 등록이 실제 클라이언트 IP를 써야 하면서도 클라이언트가 보낸 헤더로 IP를 위조할 수 없어야 한다 | `WAF_TRUSTED_PROXY`, `waf/nginx.conf.template` |
| 로그 민감 헤더 마스킹, 탐지 이벤트 최소화 | 원문 전체 전달, 본문까지 마스킹 | 세션·인증 헤더 유출을 막으면서 AI 분석에 필요한 본문은 유지한다. 본문 저장은 한계로 남긴다 | `waf/njs/headers.js`, `waf/waf-detection.lua` |
