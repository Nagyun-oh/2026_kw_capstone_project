# EC2 배포 절차서: AI 요청 outbox · 결과 재시도/DLT · E2E 계측

작성: **2026/11/05** · 상태: **작성 완료 / 미실행**

[EC2 목차](README.md) · [AWS 배포](../../06_aws_deployment.md) · [CI/CD](../../07_cicd_pipeline.md) · [로컬 복구 검증](../local/recovery-verification.md)

로컬에서 검증한 정합성 보완과 E2E 계측을 EC2에 반영하는 순서다. 이 문서는 절차만 정리하며 **커밋·push·PR·배포·DB 변경·WAF 재생성은 사용자가 승인한 뒤 직접 수행**한다. 실제 결과는 실행 시각과 함께 9절 기록에 남기고, 이 문서의 예상 결과를 실행 결과로 간주하지 않는다.

## 1. 반영 대상과 EC2 반영 방법

| 계층 | 변경 | EC2 반영 방법 | 이전 버전과의 호환 |
| --- | --- | --- | --- |
| DB | `ai_request_outbox` 테이블 추가 | **배포 전** 수동 SQL(5절). 기존 볼륨에는 초기화 SQL이 자동 실행되지 않음 | 이전 backend는 이 테이블을 사용하지 않음 |
| backend | 로그 저장과 같은 트랜잭션의 outbox 저장, 별도 발행기, 결과·로그 Consumer 예외 전파·재시도·DLT, producer `acks=all`·멱등성·시간 제한, Consumer 수동 commit(`RECORD`), `DG_TRACE` | CD 이미지 교체 | consumer group ID(`log-group`, `ai-result-group`, `waf-detection-group`) 동일 → 기존 offset 이어서 처리 |
| Kafka | `ai-result-topic.DLT`, `log-topic.DLT`(파티션 1, 보존 7일) | backend 시작 시 `NewTopic` 빈으로 생성 | 이전 backend는 DLT를 읽지 않음 |
| WAF | 응답 `X-Request-ID`·`X-DualGuard-Request-Start`, access JSON의 시작 시각·실험 표식 필드 | **배포 후** EC2 체크아웃 파일로 WAF 재생성(7절). `deploy.sh`는 WAF를 재생성하지 않음 | 이전 backend는 access JSON을 `readTree`로 읽어 추가 필드를 무시 |
| frontend | `emitE2ETrace` 호출 | CD 이미지 교체 | 자동화 브라우저가 콜백을 설치하지 않으면 동작 없음 |
| 환경 변수 | `PIPELINE_TRACE_ENABLED`(기본 false), `AI_OUTBOX_ENABLED`(기본 true) | `.env.aws` 선택 설정(6절) | 값이 없으면 Compose 기본값 사용 |

### 순서가 중요한 이유

1. **outbox 테이블은 새 backend보다 먼저 있어야 한다.** `LogService`는 `AI_OUTBOX_ENABLED` 값과 관계없이 로그 저장 트랜잭션 안에서 outbox를 저장한다(`Propagation.MANDATORY`). outbox는 JdbcTemplate을 사용하므로 `ddl-auto: validate`가 시작 시점에 테이블 누락을 잡지 못한다. 테이블이 없으면 health는 UP이어도 로그 저장이 롤백되고, 새 오류 처리기에 따라 1초 간격 2회 재시도 후 `log-topic.DLT`로 이동한다.
2. **`AI_OUTBOX_ENABLED=false`는 우회책이 아니다.** 발행기만 멈추므로 outbox가 `PENDING`으로 쌓이고 AI 분석이 진행되지 않는다.
3. **WAF 설정은 이미지 배포로 바뀌지 않는다.** 템플릿·njs는 EC2 체크아웃 파일을 bind mount하며 컨테이너 시작 시 렌더링된다. CD가 체크아웃을 바꿔도 실행 중인 WAF는 이전 설정을 유지한다. 이전 설정과 새 njs 파일은 함께 동작할 수 있지만 계측 헤더는 재생성 전까지 나오지 않는다.
4. **롤백 시 미발행 outbox가 남을 수 있다.** 이전 backend는 outbox를 읽지 않으므로 롤백 시점의 `PENDING`·`IN_FLIGHT` 작업은 AI 분석 요청이 발행되지 않는다(8절).

## 2. 실행 전 결정할 것

| 항목 | 선택지·권장 | 결정 |
| --- | --- | --- |
| 배포 시간대 | backend 재생성 시 로그인 세션 종료, WAF 재생성 시 JuiceShop 경로 짧은 중단. 팀원 공지 | 미정 |
| 백업 | 필수: 스키마 기록. 권장: EBS 스냅샷. 데이터 덤프는 크기·소요 시간 확인 후 결정 | 미정 |
| `PIPELINE_TRACE_ENABLED` | 측정이 곧 이어지면 배포 때 `true`로 함께 반영(재생성 1회). 아니면 `false` 유지 후 측정 전 backend만 재생성 | 미정 |
| 접근 방식 | SSH(docs/06 2절, 22번은 관리자 IP/32) 기준으로 작성. SSM을 쓰면 같은 명령을 root로 실행 | 미정 |
| 운영 문서 반영 | docs/06 환경 변수 표·docs/04 DB 설계에 outbox와 새 변수 추가 여부 | 미정 |

## 3. 로컬 준비: 커밋 정리 → 검증 → PR

### 3-1. 커밋 정리

현재 신규 파일 12개가 staged 상태이고 그중 11개는 작업 파일과 내용이 다르다(AM). **그대로 커밋하면 이전 내용이 들어간다.** 커밋할 파일을 명시해 다시 스테이징하고 `git diff --cached --stat`과 남은 `git diff --stat`을 확인한다. `git add -A`는 사용하지 않는다.

| 묶음 | 파일 | 비고 |
| --- | --- | --- |
| A. 앱 변경 (배포 대상) | `backend/src/main/**` 변경·신규, `backend/src/test/**` 관련 테스트(`AiRequestProducerTest` 삭제 포함), `compose.yaml`, `compose.aws.yaml`, `.env.example`, `aws.env.example`, `docs/db/security-db-schema.sql`, `docs/db/add-ai-request-outbox.sql`, `frontend/src/hooks/useWebSocket.js`, `frontend/src/utils/e2eTrace.js`·`e2eTrace.test.js`·`hooks/useWebSocket.test.js`, `waf/nginx-logging.conf.template`, `waf/nginx.conf.template`, `waf/njs/headers.js`, `waf/README.md`, `waf/tests/test_measurement_metadata.py` | outbox와 계측이 `LogService` 등에서 같은 파일에 섞여 있어 부분 스테이징보다 한 기능 커밋이 안전. 미추적 `RecoveryVerificationTest`도 여기에 포함하며 `DG_RECOVERY_DB_URL`이 있을 때만 실행돼 CI에서는 생략됨 |
| B. 실험 도구·기록 (이미지 무관) | `scripts/testing/**`, `docs/testing/**`, `frontend/src/utils/browserTrace.test.js` | `browserTrace.test.js`는 `../scripts/testing/browser_trace.js`를 읽으므로 B와 함께 둔다 |
| 별도 판단 | `AGENTS.md` | 사용자 변경. 위 묶음에 섞을지 따로 결정 |

### 3-2. 로컬 검증

| 대상 | 실행 위치·명령 | 비고 |
| --- | --- | --- |
| backend 관련 단위 | `backend/`: `.\gradlew.bat test --tests "*AiRequestOutboxPublisherTest" --tests "*PipelineKafkaErrorConfigTest" --tests "*PipelineTraceTest" --tests "*AiResultConsumerTest" --tests "*LogConsumerTest" --tests "*LogServiceTest" --tests "*ThreatServiceTest" --tests "*WafDetectionWriterTest"` | 실제 이름은 `rg --files backend/src/test`로 확인 |
| backend 전체 | DB·`local` 프로필 준비 후 `backend/`: `.\gradlew.bat test` | `contextLoads`는 outbox가 포함된 스키마 필요. `.github/workflows/ci.yml` 참고 |
| frontend | `frontend/`: `npm run build`, `npm test -- --watchAll=false --runInBand --runTestsByPath src/hooks/useWebSocket.test.js src/utils/e2eTrace.test.js` | CI는 프론트 테스트를 실행하지 않음 |
| WAF | 루트: `python -m unittest discover -s waf/tests -v` | 이전 기록상 Windows의 shell 회귀 테스트 일부는 환경 문제로 실패할 수 있음. 결과를 그대로 기록 |
| 실행기 | 루트: `.\build\e2e-venv\Scripts\python.exe -X utf8 -m unittest discover -s scripts/testing -p "test_*.py"` | 2026/11/05 114개 통과(B 묶음 검증용) |

### 3-3. PR → develop → main

1. 기능 PR(develop 대상)의 CI 통과를 확인한다. CI DB 초기화는 `security-db-schema.sql`(outbox 포함) 후 기존 `add-*.sql` 3개를 실행하므로 `add-ai-request-outbox.sql`을 CI에 추가하지 않는다. 추가하면 테이블 중복 생성으로 실패한다.
2. develop → main 릴리스 PR의 CI를 확인하고 머지한다. **머지만으로 배포되지 않는다.**
3. 배포 SHA를 확정한다. 로컬에서 `git fetch origin` 후 `git rev-parse origin/main`. 이 SHA의 SQL 해시를 기록한다.

```powershell
git show <배포SHA>:docs/db/add-ai-request-outbox.sql | python -c "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"
```

## 4. EC2 사전 점검 (읽기 전용)

SSH 접속 후 저장소에서 실행한다. 아래 두 함수는 이 문서의 명령을 줄이기 위한 셸 함수이며 파일을 만들지 않는다. DB 명령은 컨테이너 안의 `MYSQL_ROOT_PASSWORD`를 사용하므로 비밀번호를 입력·출력하지 않는다. root 비밀번호를 DB 생성 후 바꿨다면 docs/06 4-1절처럼 앱 계정 `-p` 대화형 접속을 사용한다.

```bash
cd /home/ubuntu/2026_kw_capstone_project
dc()  { sudo docker compose --env-file .env.aws -f compose.aws.yaml "$@"; }
dbq() { dc exec -T db sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -u root -D security_db --table'; }
```

```bash
# 저장소·이미지
git status --short
git log -1 --oneline
git rev-parse HEAD
grep '^IMAGE_TAG=' .env.aws
dc images
dc ps -a
# 환경 변수: 키 목록만, 비밀이 아닌 설정값만 출력
grep -oE '^[A-Z_]+=' .env.aws | sort
grep -E '^(WAF_CONSUMER_ENABLED|PIPELINE_TRACE_ENABLED|AI_OUTBOX_ENABLED|WAF_EVENT_ZONE|WAF_ID|WAF_SYNC_INTERVAL)=' .env.aws
# 자원·로그 설정
df -h /
free -m
sudo docker info --format '{{.LoggingDriver}}'
cat /etc/docker/daemon.json 2>/dev/null
# Kafka
dc exec -T kafka kafka-consumer-groups --bootstrap-server kafka:29092 --all-groups --describe
dc exec -T kafka kafka-topics --bootstrap-server kafka:29092 --list
```

| 확인 | 기준 |
| --- | --- |
| 저장소 | 추적 파일 수정 없음(있으면 CD 중단). 현재 SHA를 **롤백 대상**으로 기록 |
| 현재 이미지 | `IMAGE_TAG`와 실행 이미지가 일치. 롤백 SHA 이미지가 ECR 최근 10개 안에 있는지 확인 |
| 환경 변수 | 값은 출력·기록하지 않음. `WAF_CONSUMER_ENABLED=true` 필요(Compose 기본 false) |
| 자원 | 디스크 여유, 로그 드라이버·회전 설정 기록 |
| Kafka | 배포 전 lag와 DLT 토픽 부재 기록 |

DB 구조 확인:

```bash
dbq <<'SQL'
START TRANSACTION READ ONLY;
SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES
 WHERE TABLE_SCHEMA='security_db'
   AND TABLE_NAME IN ('network_logs','request_correlations','request_alerts','waf_detections','waf_sync_status','ai_request_outbox')
 ORDER BY TABLE_NAME;
SELECT COLUMN_NAME, COLUMN_TYPE FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA='security_db' AND TABLE_NAME='network_logs' AND COLUMN_NAME IN ('id','request_id','request_url');
SELECT CONCAT(TABLE_NAME,':',GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX)) AS unique_key
  FROM information_schema.STATISTICS
 WHERE TABLE_SCHEMA='security_db' AND NON_UNIQUE=0
   AND TABLE_NAME IN ('network_logs','waf_detections','request_alerts')
 GROUP BY TABLE_NAME, INDEX_NAME;
ROLLBACK;
SQL
```

진행 기준: `ai_request_outbox`가 **없고**, 나머지 5개 테이블이 InnoDB로 있으며, `network_logs.id`가 `bigint`, `request_url`이 `text`, UNIQUE에 `network_logs:request_id`·`waf_detections:request_id`·`waf_detections:threat_id`·`request_alerts:alert_key`·`request_alerts:alert_id`가 있다. 하나라도 다르면 이전 `add-*.sql` 적용 상태부터 따로 확인하고 진행하지 않는다. `ai_request_outbox`가 이미 있으면 구조를 비교하고 SQL을 다시 실행하지 않는다.

## 5. 백업과 SQL 적용 (배포 전)

### 5-1. 백업

```bash
sudo install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/db-backups
dc exec -T db sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump -u root --no-data --single-transaction security_db' \
  | sudo -u ubuntu tee /home/ubuntu/db-backups/security_db-schema-$(date -u +%Y%m%dT%H%M%SZ).sql >/dev/null
```

백업은 저장소 밖에 둔다. 저장소 안에 두면 이후 작업 트리 확인을 어지럽힌다. 데이터 보호가 필요하면 콘솔에서 EBS 스냅샷을 만든다. 스냅샷·덤프 생성은 복구 검증이 아니다(docs/06 체크리스트 미완료 항목).

### 5-2. 배포 SHA의 SQL 적용

`git fetch`는 작업 트리를 바꾸지 않는다. CD도 같은 fetch를 수행한다. 적용할 SQL은 배포할 SHA에서 직접 읽어 해시를 3-3절 값과 대조한다.

```bash
sudo -u ubuntu -H git fetch --quiet origin main
SHA=<배포SHA 40자리>
sudo -u ubuntu -H git show "$SHA:docs/db/add-ai-request-outbox.sql" | sha256sum
sudo -u ubuntu -H git show "$SHA:docs/db/add-ai-request-outbox.sql" | dbq
```

SQL에는 `IF NOT EXISTS`와 `USE`가 없다. `dbq`가 `-D security_db`를 지정한다. MySQL 8의 `CREATE TABLE`은 원자적 DDL이므로 실패하면 테이블이 남지 않는다. 오류가 나면 **배포하지 않고** 오류 메시지와 4절 결과를 비교한다. 이 시점에는 이전 backend가 계속 동작하며 새 테이블을 사용하지 않는다.

적용 확인:

```bash
dbq <<'SQL'
SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA='security_db' AND TABLE_NAME='ai_request_outbox' ORDER BY ORDINAL_POSITION;
SELECT INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS cols FROM information_schema.STATISTICS
 WHERE TABLE_SCHEMA='security_db' AND TABLE_NAME='ai_request_outbox' GROUP BY INDEX_NAME;
SELECT CONSTRAINT_NAME, REFERENCED_TABLE_NAME FROM information_schema.REFERENTIAL_CONSTRAINTS
 WHERE CONSTRAINT_SCHEMA='security_db' AND TABLE_NAME='ai_request_outbox';
SQL
```

기준: 컬럼 10개, `PRIMARY(log_id)`, `idx_ai_outbox_ready(state,available_at,log_id)`, `fk_ai_outbox_log → network_logs`.

## 6. 환경 변수 (선택, 배포 전)

```bash
nano .env.aws        # 소유자 ubuntu, 권한 600 유지
dc config --quiet; echo $?
```

- `PIPELINE_TRACE_ENABLED`: 2절 결정값. `DG_TRACE`는 단계·requestId·logId·threatId·alertId·시각만 기록하며 IP·본문은 남기지 않는다. 로그 회전이 없다면 4절에서 확인한 디스크 여유를 고려한다.
- `AI_OUTBOX_ENABLED`: 설정하지 않거나 `true`. `false`로 두지 않는다(1절).
- `WAF_CONSUMER_ENABLED=true` 확인.
- CD가 backend를 재생성하므로 여기서 바꾼 값은 배포와 함께 반영된다. 배포 후 바꾸면 `dc up -d --no-build --no-deps --force-recreate backend`가 별도로 필요하다.

## 7. 배포 실행과 직후 확인

### 7-1. Deploy to EC2

GitHub → Actions → **Deploy to EC2** → Run workflow, 브랜치 `main`, `sha` 비움. 실행 URL과 배포 SHA를 기록한다. `deploy.sh`는 앱 이미지 3개를 pull한 뒤 `up -d --no-build --remove-orphans`로 backend·frontend·ai를 재생성하고 health를 최대 300초 기다린다. 인프라 서비스와 WAF는 설정이 바뀌지 않았으므로 재생성되지 않는다.

### 7-2. 앱 확인

```bash
git log -1 --oneline
dc images && dc ps -a
dc logs --since=10m backend | grep -E 'ERROR|AI outbox dispatch failed|AI outbox retry scheduled|Kafka processing failed|DG_TRACE_UNAVAILABLE|DG_TRACE_WRITE_FAILED' | tail -n 40
dc exec -T kafka kafka-topics --bootstrap-server kafka:29092 --list | grep -E '\.DLT$'
dc exec -T kafka kafka-run-class kafka.tools.GetOffsetShell --bootstrap-server kafka:29092 --topic log-topic.DLT
dc exec -T kafka kafka-run-class kafka.tools.GetOffsetShell --bootstrap-server kafka:29092 --topic ai-result-topic.DLT
dbq <<'SQL'
SELECT state, COUNT(*) AS cnt, MAX(attempts) AS max_attempts FROM ai_request_outbox GROUP BY state;
SELECT TIMESTAMPDIFF(SECOND, MIN(created_at), UTC_TIMESTAMP(6)) AS oldest_unsent_age_s
  FROM ai_request_outbox WHERE state <> 'SENT';
SQL
```

기준: 앱 3개 실행·health 성공, 위 오류 패턴 없음, DLT 토픽 2개 존재·offset 0, outbox가 `SENT`로 진행되고 미발행 작업이 오래 남지 않음, 4절보다 lag가 늘어나지 않음. outbox는 배포 이후 저장된 로그부터 생긴다. `GetOffsetShell`의 실행 방식이 이미지 버전과 맞지 않으면 명령 오류를 기록하고 consumer group 확인으로 대신한다.

### 7-3. WAF 재생성 (배포 후)

```bash
git diff <롤백SHA> HEAD --stat -- waf/
dc up -d --force-recreate --no-deps waf
dc ps waf
dc exec -T waf nginx -t
curl -sS -o /dev/null -D - http://127.0.0.1:8081/ | grep -iE '^(x-request-id|x-dualguard-request-start):'
dc logs --since=2m waf | grep -iE 'sync|blacklist' | tail -n 20
```

관리자 PC에서 호스트 Nginx 통과를 확인한다.

```powershell
curl.exe -sS -o NUL -D - https://security-juiceshop-kw.duckdns.org/ | Select-String -Pattern '^(x-request-id|x-dualguard-request-start):'
```

기준: `nginx -t` 성공, 두 응답 헤더가 내부·HTTPS 모두에서 보임(requestId 32자 16진수, 시작 시각은 소수 3자리 epoch 초), 동기화 로그에 마지막 적용 상태 복원·보고가 보임. 대시보드 WAF 상태의 적용 version이 재생성 전과 같은지 확인한다. 이 확인 요청은 운영 로그에 각각 1건으로 저장된다. 내부 `curl`의 출발지는 Docker 게이트웨이(차단 제외)다.

### 7-4. 단건 연결 확인

공격 probe는 보내지 않는다. 발생기 IP 정책을 결정하기 전에는 같은 요청에서 WAF·AI가 함께 탐지되면 자동 차단이 생길 수 있다. 7-3의 HTTPS 응답에서 받은 `X-Request-ID`로 저장·발행·AI 처리를 확인한다.

```bash
RID=<X-Request-ID 값>
dbq <<SQL
SELECT n.id AS log_id, n.status_code, o.state, o.attempts,
       TIMESTAMPDIFF(MICROSECOND, o.created_at, o.published_at)/1000 AS dispatch_ms,
       JSON_UNQUOTE(JSON_EXTRACT(n.raw_log,'$.request_start_epoch_s')) AS request_start
  FROM network_logs n LEFT JOIN ai_request_outbox o ON o.log_id = n.id
 WHERE BINARY n.request_id = BINARY '$RID';
SQL
dc logs --since=5m backend | grep -E "AI analysis result received\. logId=<log_id>\b"
```

기준: 로그 1행, outbox `SENT`, AI 결과 처리 로그 1건, `request_start`가 응답 헤더 값과 같음. `dispatch_ms`는 DB 시계만 사용한 값이며 성능 결과로 쓰지 않는다. `PIPELINE_TRACE_ENABLED=true`라면 같은 requestId의 `DG_TRACE LOG_COMMITTED`·`AI_RESULT_COMMITTED`도 확인한다.

## 8. 롤백

| 상황 | 판단 근거 | 조치 |
| --- | --- | --- |
| SQL 실패 | 5-2 오류 | 배포하지 않음. 원인 확인 전 재실행하지 않음 |
| health 실패·앱 오류 | `deploy.sh` 실패, 7-2 오류 패턴, `log-topic.DLT` offset 증가, 미발행 outbox 증가 | 아래 앱 롤백 |
| WAF 재생성 실패 | `nginx -t` 실패, WAF 재시작 반복 | `dc logs waf` 확인 후 이전 체크아웃 템플릿으로 다시 재생성(앱 롤백과 함께) |

**앱 롤백 절차**

1. 미발행 작업 기록: `SELECT log_id, state, attempts, last_error_code FROM ai_request_outbox WHERE state <> 'SENT' ORDER BY log_id;` 결과의 개수와 log_id 범위를 남긴다. 발행기가 정상이면 0이 될 때까지 기다린다. 이전 backend는 이 작업을 처리하지 않으므로 롤백 후 해당 로그는 AI 분석 요청이 발행되지 않는다. 재처리는 별도로 결정한다.
2. Actions → Deploy to EC2, 브랜치 `main`, `sha`에 4절의 롤백 SHA(ECR 보관 확인)를 입력한다.
3. 체크아웃이 이전 SHA로 돌아가 WAF 템플릿도 디스크에서 이전 상태가 된다. 실행 중 WAF는 새 설정을 유지하며 이전 backend와도 호환된다. 계측 헤더까지 되돌리려면 `dc up -d --force-recreate --no-deps waf`를 다시 실행한다.
4. `PIPELINE_TRACE_ENABLED`를 바꿨다면 되돌린다. 이전 backend는 이 값을 사용하지 않는다.
5. DLT 메시지는 7일 보존된다. 이전 backend는 DLT를 읽지 않는다. `scripts/testing/kafka_replay.py`는 로컬 검증용 선택 재처리 도구이며 운영 재처리에 쓰려면 대상·중복 영향을 따로 검토한다.

**DB는 기본적으로 되돌리지 않는다.** 이전 backend는 `ai_request_outbox`를 사용하지 않으므로 남겨 둬도 동작에 영향이 없다. 테이블 삭제는 미발행 작업 확인과 별도 승인 후에만 수행한다. 이미지 롤백과 DB 롤백은 별개다.

## 9. 실행 기록

실행 후 비밀값을 제외하고 `docs/testing/ec2/evidence/<YYYYMMDD>-deploy-outbox-trace.json`에 남기고 [EC2 목차](README.md)의 P2를 갱신한다. 이 배포는 성능 실험이 아니므로 실험 보고서를 만들지 않는다.

- 실행자·시각(KST), 롤백 SHA, 배포 SHA, Actions 실행 URL, 앱 이미지 3개 digest, WAF 이미지 digest
- 4절 사전 점검 결과(키 목록·설정값·자원·lag·DB 구조), 백업 방식·위치·크기
- SQL 해시·적용 시각·확인 결과, 환경 변수 변경 키
- 7-2~7-4 확인 결과와 기준 충족 여부, 실패·우회·미확인 항목
- 롤백 여부와 미발행 outbox 처리
