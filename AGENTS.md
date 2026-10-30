# AGENTS.md

## 목적과 작업 원칙

DualGuard는 WAF·AI 탐지를 결합한 졸업 프로젝트다. 기능뿐 아니라 설계 근거, 장애 처리, 검증 결과를 포트폴리오에서 설명할 수 있게 유지한다.

- 작업 시작 시 `git status --short`, 현재 브랜치, 관련 diff를 확인한다. 기존 사용자 변경을 덮어쓰거나 작업 범위에 섞지 않는다.
- 검토·설명·직접 적용할 코드 안내를 요청받았다면 파일을 수정하지 않는다. 수정 요청은 해당 범위에서 완료하고, 커밋·push·배포로 임의 확대하지 않는다.
- 작은 변경을 우선한다. 요청과 관계없는 리팩터링, 의존성 추가, 기능 확장은 피한다.
- 코드와 실행 설정을 먼저 확인한다. 문서·예제 환경 변수만으로 운영 상태나 DB 적용 여부를 단정하지 않는다.
- 설명과 문서는 한국어로 작성한다. 변경 계층, 원인·해결, 실행한 검증과 남은 한계를 간결하게 보고한다.

## 실제 구조와 데이터 흐름

- `backend/`: Java 17, Spring Boot, JPA, Spring Kafka, 세션 인증, WebSocket/STOMP.
- `frontend/`: React + Create React App(`react-scripts`), Axios. 운영에서는 Nginx가 빌드 산출물을 제공한다.
- `AI_new/`: 현재 Compose·CI·배포 대상인 Python/FastAPI AI 서비스. `AI/`는 이전 코드이므로 대상을 혼동하지 않는다.
- `waf/`: Nginx/ModSecurity, Fluent Bit 설정, 블랙리스트 동기화, 로그 회전, 관련 테스트.
- `compose.yaml`: 로컬. `compose.aws.yaml`: EC2. DB는 MySQL, 메시지 브로커는 Kafka/Zookeeper.

```text
사용자 → EC2 Nginx(HTTPS) → WAF → JuiceShop
WAF access.log → Fluent Bit → log-topic → backend → network_logs
backend → ai-request-topic → AI_new → ai-result-topic → backend → AI 탐지 저장
WAF audit 이벤트 → Fluent Bit → waf-detection-topic → backend → WAF 탐지 저장
탐지·요청별 알림 기록 → DB 커밋 후 전송·재시도 → WebSocket → 대시보드
DB 블랙리스트 → 인증된 스냅샷 조회 → WAF 규칙 적용 → 적용 결과 보고 → 상태 표시
```

일반 AI 분석 경로는 Kafka 비동기 처리다. HTTP 추론 API가 존재해도 기본 파이프라인을 동기 HTTP 호출로 설명하지 않는다. AI 분석·블랙리스트 등록은 이미 실행된 요청을 소급 차단하지 않는다.

## 작업별 진입점

백엔드 Java 경로의 기준은 `backend/src/main/java/com/example/security_log_system/`이다. 아래 이름은 이 경로 안에서 찾는다.

| 작업 | 우선 확인할 파일·경로 |
| --- | --- |
| 전체 로그·검색 | `LogController`, `LogService`, `LogSearchCondition`, `LogSpecification` |
| AI·WAF 탐지 저장 | `ThreatService`, `WafDetectionConsumer`, `WafDetectionService`, `WafDetectionWriter` |
| 요청 연결·자동 차단 | `RequestCorrelationService`, `AutoBlacklistPolicyService`, `BlacklistService` |
| 통합 위협 조회 | `ThreatController`, `ThreatRepository`, `GroupedThreatResponseDto` |
| 커밋 후 통합 알림 | `RequestAlertService`, `RequestAlertPublisher`, `RequestAlertDispatcher` |
| 블랙리스트 동기화·보고 | `WafSyncController`, `WafSyncSecurityConfig`, `WafSyncTokenFilter`, `WafSyncStatusService`, `waf/sync/` |
| 화면·목록·자동 갱신 | `frontend/src/Dashboard.js`, `frontend/src/components/`, `frontend/src/hooks/` |
| API·인증·시간 표시 | `frontend/src/api/`, `frontend/src/config.js`, `frontend/src/utils/dateTime.js` |
| 로고·사이트 제목 | `frontend/public/`, `LoginPage`, `DashboardLayout` |
| DB·배포·CI | `docs/db/`, `scripts/deploy.sh`, `.github/workflows/` |

이름이 바뀌었다면 `rg --files`로 확인한다. 파일을 찾기 위해 저장소 전체 내용을 반복해서 출력하지 않는다.

## 보존해야 할 동작

### 요청 연결·차단·알림

- WAF가 생성한 공통 `request_id`로 HTTP 로그와 WAF 탐지를 연결한다. 대소문자 구분을 보존하고 클라이언트 ID, IP·시각 조합으로 대체하지 않는다.
- 전체 로그와 WAF 이벤트는 순서가 바뀌어 도착할 수 있다. 원본 로그가 없더라도 WAF 이벤트를 보존하고, 가짜 로그 ID를 만들지 않는다.
- 현재 정책은 **WAF 또는 AI 탐지 시 기록·통합 알림**, **같은 요청에서 WAF와 AI 모두 탐지하고 IP도 일치할 때 자동 블랙리스트 등록**이다. 수동 등록·삭제도 지원한다.
- 자동 등록의 원인 위협은 두 탐지 중 먼저 저장된 ID다. 블랙리스트 삭제는 원본 로그·탐지 이력을 삭제하지 않는다.
- 요청별 잠금, UNIQUE 제약, 저장 트랜잭션을 함께 유지한다. 상관관계·정책 서비스의 `MANDATORY`와 호출자의 트랜잭션·격리 수준을 임의로 분리하지 않는다.
- 탐지와 알림 전송 대기 정보를 같은 트랜잭션에 저장한다. 커밋 전 발송이나 Kafka 재처리에 따른 중복 팝업을 만들지 않는다. WebSocket 전달을 종단 간 exactly-once라고 주장하지 않는다.
- 통합 위협 목록은 요청 단위로 그룹화한 뒤 검색·페이지 처리한다. 그룹 건수와 개별 탐지 건수를 혼동하지 않고, WAF 상세에는 실제 WAF 탐지 ID를 사용한다.

### WAF 적용 상태

- 일반 공격 규칙의 `DetectionOnly`와 블랙리스트 IP의 `403` 차단은 별개다. Spring 백엔드는 JuiceShop 요청을 직접 받는 차단 계층이 아니다.
- DB 등록과 WAF 적용 사이에는 지연·실패가 있다. 적용 version 일치, 상태 보고 수신, 실제 요청의 403 검증을 구분한다.
- 정상적인 빈 목록은 차단 해제를 뜻한다. 조회·JSON 검증·파일 교체·reload 실패는 마지막 정상 설정을 유지·복구해야 한다.
- `attemptedVersion`과 `appliedVersion`, `excludedIps: null`과 `[]`의 의미를 보존한다. 보고 실패 때문에 적용 완료한 차단을 되돌리지 않는다.
- 보고 중단은 상태 미확인이며 차단 해제를 뜻하지 않는다. 기본 동기화·보고 주기는 10초, stale 기준은 60초다. 계약은 `docs/waf-sync-status-api.md`를 따른다.
- 프록시·게이트웨이 제외 IP를 고려한다. ‘적용 확인’을 ‘모든 등록 IP 차단 완료’로 표시하지 않는다. 실제 IP 신뢰 설정을 완화하거나 임의의 `X-Forwarded-For`를 신뢰하지 않는다.

### 인증·시간·구현 계층

- 관리자 API는 세션 인증과 CSRF 보호를 사용한다. 프론트는 기존 `apiClient`의 쿠키·CSRF 처리를 재사용한다.
- 내부 API는 `X-WAF-Sync-Token` 전용 인증이다. `GET /internal/waf/blacklist`, `POST /internal/waf/sync-status`만 명시적으로 허용하며 관리자 세션으로 대체하지 않는다.
- CSRF 예외는 내부 보고 경로로 제한한다. 전역 비활성화나 관리자 API의 인증 해제로 테스트를 통과시키지 않는다.
- DB 시간은 기존 `UtcDateTime`의 UTC 기준 `LocalDateTime`, API는 오프셋 있는 응답, 화면은 `Asia/Seoul` 표시 규칙을 따른다. 수동으로 9시간을 더하거나 전역 시간대를 바꿔 부분 오류를 덮지 않는다.
- 컨트롤러·Kafka Consumer는 얇게, 업무 로직은 서비스에 둔다. 생성자 주입과 DTO·검증을 사용하고, 토픽·그룹 ID·재시도·DLT 설정 변경 시 영향과 문서를 함께 확인한다.
- AI 장애·잘못된 메시지를 정상 탐지 결과로 위장하지 않는다. 가짜 추론은 테스트임을 명시한다.
- React의 API 호출·상태 관리는 기존 hooks/API 계층을 따른다. 자동 갱신은 검색·페이지를 유지하고, 중복 요청·오래된 응답·화면 해제 후 갱신을 처리한다.

## DB 변경

- `ddl-auto: validate`이므로 엔티티 수정만으로 기존 DB가 바뀌지 않는다. 현재 Flyway 설정만으로 SQL이 자동 실행된다고 가정하지 않는다.
- 컬럼·테이블 변경은 엔티티, 기존 DB용 `docs/db/` SQL, 새 DB용 `security-db-schema.sql`, 필요 시 CI 초기화 순서까지 확인한다.
- 기존 DB에 초기 스키마나 추가 SQL을 일괄 재실행하지 않는다. 대상 DB와 현재 구조를 먼저 확인하고 필요한 변경만 적용한다.
- 로컬·EC2 적용 여부를 각각 확인한다. 이미지 롤백과 DB 롤백은 별개다. 운영 SQL 실행·데이터 삭제는 문서 수정의 일부로 수행하지 않는다.
- `network_logs.request_url`은 현재 `TEXT`다. 긴 URL 처리 시 DTO·저장·조회·WAF 경로까지 함께 확인한다.

## 효율적인 탐색·검증

1. 요청과 관련된 계층·파일·테스트를 좁히고 `rg`로 검색한다. `node_modules`, `build`, 모델·데이터·로그 대용량 파일은 기본 탐색에서 제외한다.
2. 원인과 최소 변경을 정한 뒤 수정한다. 반복되는 사실·긴 실행 절차는 이 파일에 복제하지 않고 관련 문서를 참조한다.
3. 변경에 맞는 검증부터 실행한다. 통과한 검증은 새 변경·실패·미해결 위험이 없으면 반복하지 않는다.
4. 정책·검증·장애 처리에는 의미 있는 테스트를 추가한다. 단순 문구·CSS 변경에 구현을 그대로 복제하는 테스트는 추가하지 않는다.
5. 마지막에 diff와 변경 범위를 확인한다. 테스트 성공, 빌드 성공, 모의 환경 검증, 실제 통합 검증을 나누어 보고한다.

명령의 실행 위치를 구분한다. 아래는 Windows PowerShell 기준이다.

| 변경 | 실행 위치와 검증 |
| --- | --- |
| 백엔드 특정 로직 | `backend/`에서 ` .\gradlew.bat test --tests "*관련클래스Test"`의 패턴을 실제 테스트 이름으로 바꿔 실행 |
| 백엔드 전체 | DB·프로필 준비 후 `backend/`에서 `.\gradlew.bat test` |
| 프론트 | `frontend/`에서 `npm run build`; 의존성이 없거나 lock 변경 시 `npm ci` 선행 |
| WAF 스크립트 | 루트에서 `python -m unittest discover -s waf/tests -v` |
| AI Python 문법 | 루트에서 `python -m compileall -q AI_new`; 추론·모델 검증은 해당 변경과 CI 절차에 맞게 추가 |
| 문서만 변경 | `git diff --check`, 참조 경로·명령·예시 확인. 애플리케이션 전체 테스트는 불필요 |

- 전체 백엔드 테스트의 `contextLoads`는 준비된 MySQL 스키마와 `local` 프로필·DB 접속 설정이 필요하다. Compose의 `--env-file`은 호스트 Gradle 환경 변수를 설정하지 않는다. `.github/workflows/ci.yml`을 참고한다.
- 실제 DB가 필요한 테스트에는 격리된 테스트 DB를 사용한다. 연결 오류 때문에 테스트를 삭제하거나 운영 DB를 초기화하지 않는다. 기본 설정의 Consumer·스케줄러 실행 여부도 확인한다.
- `bootJar`·프론트 빌드·AI `/health` 성공만으로 전체 테스트·탐지 정확도·차단 성공을 주장하지 않는다. WAF 단위 테스트와 실제 Nginx·403 검증도 구분한다.
- 환경·권한·의존성 때문에 실행하지 못했다면 시도한 명령과 막힌 이유를 명시한다.

## Docker와 배포

- 로컬 명령은 루트의 `compose.yaml`과 `.env`를 사용한다. Compose 서비스명은 `db`이며 `security-mysql`은 컨테이너명이다.
- 로컬은 외부 `security-net`, Kafka/Zookeeper 데이터 볼륨, MySQL 데이터 경로 준비가 필요하다. 새 환경은 `docs/05_infra_deployment.md`와 `.env.example`을 확인한다.
- 재빌드 예: `docker compose --env-file .env -f compose.yaml up -d --build --no-deps backend frontend`. `--build`, `--no-deps`는 `up` 뒤에 둔다. 의존 서비스가 준비됐을 때만 `--no-deps`를 사용한다.
- 소스 변경은 이미지 재빌드·컨테이너 재생성이 필요하다. `restart`만으로 갱신되지 않는다. `frontend/build/`나 컨테이너 내부 정적 파일을 직접 고쳐 영구 변경으로 삼지 않는다.
- Kafka unhealthy는 로그·healthcheck·볼륨 연결을 먼저 확인한다. 데이터 볼륨 삭제·`down -v`·prune을 일반 해결책으로 쓰지 않는다.
- PowerShell에서 여러 줄 Python을 컨테이너에 전달할 때는 `$probeCode | docker exec -i security-ai-local python -`처럼 표준 입력을 사용한다.
- 현재 배포 설정은 `main` 대상 `workflow_dispatch` 수동 실행이다. 보통 기능 PR → `develop` → 배포 PR → `main` → Actions 실행 순서다. 머지만으로 배포됐다고 판단하지 않는다.
- SHA 입력이 없으면 새 이미지를 빌드하고, 기존 SHA 지정은 이미 존재하는 이미지로 되돌리는 경로다. EC2 배포는 SSM·`scripts/deploy.sh`가 체크아웃을 수행하므로 수동 `git pull`을 필수 단계로 추가하지 않는다.
- 운영 변경은 `docs/06_aws_deployment.md`, CI/CD는 `docs/07_cicd_pipeline.md`를 따른다. 워크플로·Compose·배포 스크립트와 문서가 다른 경우 실제 코드를 확인하고 함께 맞춘다. AWS IAM·실행 중 컨테이너 상태는 별도 확인 대상이다.

## Git·보안·완료 보고

- 사용자 지정 브랜치와 기존 작업을 존중한다. 승인되지 않은 force-push·브랜치 삭제·이력 재작성·변경 폐기를 하지 않는다.
- 커밋 메시지는 `feat:`, `fix:`, `docs:`, `test:`, `refactor:` 등 간결한 conventional 형식을 따른다.
- `.env`, 인증 토큰, AWS 키, DB 비밀번호, 모델 바이너리, 대규모 데이터·로그·생성 산출물은 출력하거나 커밋하지 않는다. 환경 예제에는 자리표시자를 쓴다.
- `.gitignore`를 지키고, 전체 환경 값이 펼쳐진 Compose 설정이나 민감한 요청 본문을 디버깅 출력으로 남기지 않는다.
- API·실행 흐름·설정 변경은 관련 `docs/`와 예제 환경 설정을 갱신한다. 이 문서는 작업 진입점과 규칙을 유지하고 상세 설계는 해당 문서에 둔다.
- 완료 시 **변경 파일·계층 / 핵심 변경과 이유 / 실제 검증 결과 / 남은 TODO·제한**을 짧게 정리한다. 수행하지 않은 검증이나 운영 반영을 완료로 표현하지 않는다.
