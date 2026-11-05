DualGuard 프로젝트의 기존 작업을 이어서 도와줘.

[기준과 작업 환경]

- 전달문 갱신일: 2026/11/05, Asia/Seoul.
- 작업 폴더: C:/Projects/2026_kw_capstone_project
- OS/Shell: Windows / PowerShell.
- 갱신 시 확인한 브랜치: test/experiment.
- 로컬 HEAD: 39de94d8. 실제 실험에는 커밋되지 않은 변경도 포함돼 있으므로 HEAD만으로 실험 버전을 설명하지 않는다.
- staged·unstaged·untracked 변경이 많이 섞여 있다. 일부 AM 파일은 staged 내용과 현재 작업 파일이 다르다.
- 시작할 때 git status --short, git branch --show-current, 관련 git diff와 git diff --cached부터 확인한다. 필요한 새 파일도 읽는다.
- 기존 변경·실험 원본을 덮어쓰거나 초기화하지 않는다. 커밋·push·배포·운영 DB 변경은 임의로 수행하지 않는다.
- 설명과 보고서는 한국어로 작성한다.
- 나는 실험 실행·수집·보고를 자동화하고, 발견한 병목의 개선은 원리를 이해하며 진행하고 싶다.
- 아래 실측 결과는 2026/11/03 기록이다. 2026/11/05에는 전달문·자료 경로를 정리했다. 현재 컨테이너 기동·EC2 배포·DB 적용 상태를 오늘 새로 확인한 것으로 간주하지 않는다.

[가장 중요한 최신 진행 방향]

로컬 검증은 다음까지 완료했다.

1. 계측·실제 관리자 브라우저의 E2E 연결.
2. AI 결과 처리 경합·예외 삼킴 보완과 격리 복구 검증.
3. 보완 후 1RPS × 120초 × 3회 재측정과 단계 PASS.
4. 추가 3RPS·5RPS × 120초를 각각 1회 예비 확인, 두 회차 PASS.

과거 전달문의 “로컬 3·5RPS 생략”은 이후 수행한 예비 확인을 반영하지 않은 설명이다.
현재는 3·5RPS 각 1회까지 마쳤고, 이 두 부하의 정식 3회 반복 단계는 수행하지 않았다.
로컬 추가 부하는 여기서 마무리하고 EC2 실행·계측 준비로 이동한다.

앞으로의 순서:
EC2 대상 코드·이미지·DB 적용 여부와 접근·수집 경로 확인
→ EC2용 실행·계측 연결 구현
→ 소량 연결 검증·예비 측정
→ 해당 환경의 목표·부하 상한·중단·복구 기준 확정
→ 1→3→5RPS를 출발점으로 단계적 기준 측정
→ 관측한 병목의 원인 확인
→ 해당 부분 개선
→ 같은 EC2 조건에서 재측정.

EC2 성능 실험 결과는 현재 기록에 없다. 로컬 기준을 그대로 EC2 합격 기준으로 확정하거나,
사용 시간·대상·관측 경로가 정해지기 전에 운영 부하를 시작하지 않는다.

현재까지 DB 부하 최적화는 미실행이다. outbox로 DB 작업이 늘었지만 DB가 병목이라는 근거는 없다.
쿼리 호출 수·지연, 커넥션·락 대기, outbox 적체, AI 처리·Kafka lag를 관측한 뒤 개선 대상을 선택한다.

조사할 병목과 포트폴리오 사례 수·종류를 미리 고정하지 않는다. 기존 AI·WAF 파이프라인 실험은 완료한 이력이다.
DB 조회·집계·페이지 처리·API 응답·락·AI·Kafka·수집·알림 등 실제 관측한 문제를 따라 조사하며 예시 밖의 원인도 검토한다.
새로운 API 조회 실험은 해당 경로의 목표·정확성·지연·부하·필수 증거를 정하고, 관련 없는 탐지·알림 검증을 일괄 요구하지 않는다.
위 1→3→5RPS는 기존 파이프라인의 출발안이다. 다른 대상의 부하·기간·반복·상한은 측정 목적과 준비 상태에 맞게 별도로 확정한다.
근거 확보 후 최소 개선과 동일 조건 재측정을 진행하고 원인 미확정·개선 효과 없음도 기록한다.

[먼저 읽을 문서]

1. C:/Projects/2026_kw_capstone_project/AGENTS.md
2. C:/Projects/2026_kw_capstone_project/docs/testing/README.md
3. C:/Projects/2026_kw_capstone_project/docs/testing/local/README.md
4. C:/Projects/2026_kw_capstone_project/docs/testing/local/runs/20261103T204004+0900-local-e2e-prechecks-r21.md
5. C:/Projects/2026_kw_capstone_project/docs/testing/ec2/README.md

문제 원인·전후 비교·계약을 확인할 때:

- C:/Projects/2026_kw_capstone_project/docs/testing/local/20261103-rps1-baseline-review.md
- C:/Projects/2026_kw_capstone_project/docs/testing/local/recovery-verification.md
- C:/Projects/2026_kw_capstone_project/docs/testing/local/runs/20261103-local-e2e-rps1-after-outbox-stage.md
- C:/Projects/2026_kw_capstone_project/docs/testing/local/e2e-plan-v2.md
- C:/Projects/2026_kw_capstone_project/docs/testing/local/e2e-plan-v2.json
- C:/Projects/2026_kw_capstone_project/docs/testing/local/e2e-runner.md
- C:/Projects/2026_kw_capstone_project/docs/testing/local/prechecks.md

최신 상태는 해당 환경 README의 최근 기록과 실제 증거를 대조한다.
과거 보고서와 초기 실행기 이력의 “다음 작업·미실행”은 작성 당시 상태다.
기계 명세와 과거 보고서의 판정은 현재 상태에 맞추려고 소급 변경하지 않는다.
전체 원본 로그를 처음부터 모두 출력하지 않고 필요한 집계·근거만 확인한다.

[2026/11/05 로컬 자료 경로 정리]

사용자 요청으로 로컬 문서·보고서·공유 증거를 docs/testing/local/ 아래로 모았다.

- 로컬 회차 보고서·집계 27개: docs/testing/local/runs/
- 로컬 공유 증거 JSON 10개: docs/testing/local/evidence/
- 초기 예비 실험 정리: docs/testing/local/preliminary-summary.md
- 공통 가이드에서 분리한 초기 로컬 실행기·구현 이력: docs/testing/local/runner-v1.md
- 옛 경로→현재 경로와 파일 해시: docs/testing/local/path-migration-20261105.json
- 공통 기록 규칙·템플릿·이 전달문: docs/testing/ 바로 아래.
- 향후 EC2 보고서·증거: docs/testing/ec2/runs/, docs/testing/ec2/evidence/.

실행 코드와 단위·통합 테스트는 기존 scripts/testing/, backend/src/test/, frontend/src/ 위치를 사용한다.
로컬 실행기의 새 보고서 저장 경로는 docs/testing/local/runs/로 맞췄다.
이 변경은 보고서 경로 정리이며 측정·합격·중단 기준 변경이 아니다.
경로 변경 후 실행기 모의 테스트 114개가 통과했다. 새 E2E 부하·운영 접속을 실행한 결과는 아니다.

실행 원본 build/test-runs/<실험-ID>/는 이동·수정하지 않았다.
기존 공유 증거 JSON·단계 집계 JSON의 내용·해시도 보존했다.
과거 원본 manifest·JSON에 docs/testing/runs 또는 docs/testing/evidence가 남아 있으면
이동 대조표로 현재 문서를 찾는다. 과거 경로를 고치려고 증거 파일을 다시 저장하지 않는다.

[구조·담당 범위·보존할 정책]

- backend: Java 17 / Spring Boot / JPA·JDBC / Spring Kafka / MySQL.
- frontend: React / 세션 인증 / WebSocket·STOMP.
- AI_new: 현재 Compose·배포 대상 Python/FastAPI AI 서비스. AI/는 이전 코드다.
- waf: Nginx·ModSecurity / Fluent Bit / 블랙리스트 동기화.

요청: 사용자 → EC2 Nginx(HTTPS) → WAF → JuiceShop.

AI: WAF access.log → Fluent Bit → log-topic → backend → 원본 로그·AI 요청 outbox 저장
    → 커밋된 outbox 별도 발행 → ai-request-topic → AI_new
    → ai-result-topic → backend → 결과 처리·탐지 저장.

WAF: audit 이벤트 → Fluent Bit → waf-detection-topic → backend → WAF 탐지 저장.

알림: 탐지·요청별 알림 대기를 같은 트랜잭션에 저장 → 커밋 후 별도 전송·재시도
      → WebSocket → 실제 관리자 브라우저.

내 담당은 서버 처리량·지연·자원·적체·장애 복구·데이터/알림 정합성이다.
탐지율·오탐률·공격 유형별 판정은 보안 팀원 범위다.

- WAF가 생성한 공통 requestId로 원본 로그·WAF·AI 결과를 연결한다. 대소문자를 보존한다.
- WAF 또는 AI 탐지 시 기록·통합 알림.
- 같은 요청에서 WAF와 AI 모두 탐지하고 IP도 일치하면 자동 블랙리스트 등록.
- 수동 등록·삭제 지원. DB 등록과 실제 WAF 적용·403 차단은 구분한다.
- 요청별 잠금·UNIQUE·트랜잭션과 중복 결과·알림 처리 규칙을 유지한다.
- 관리자 세션·CSRF, 내부 WAF 토큰 인증을 유지한다.
- 데이터·offset 초기화, 임의의 전달 IP 신뢰, 차단 정책 완화로 실험을 통과시키지 않는다.

[r15에서 발견한 문제와 보완]

기존 r15는 HTTP 121건 / DB 로그 121건 / AI 완료 119건이었고 최종 Kafka lag는 0이었다.
AI 요청 발행이 원본 로그 저장 트랜잭션 안에서 이루어져 빠른 AI 결과가 커밋을 앞지를 수 있었다.
결과 Consumer의 LogEntry not found 예외를 로그로만 남기고 정상 반환해 Kafka 오류 처리기로 전달하지 않았다.
이 때문에 업무 미완료가 조용히 남았다. 정확한 관측·진단 한계는 baseline-review를 따른다.

보완한 책임은 두 가지다.

1. 요청 발행: 원본 로그·outbox를 같은 트랜잭션에 저장하고 별도 발행기가 커밋된 작업만 선점.
   Kafka ACK를 확인한 뒤 SENT. 실패는 대기·재시도 상태로 보존하고 선점 중 종료는 리스 만료 후 복구.
2. 결과 처리: Consumer 업무 예외 전파 → 제한 재시도 → DLT 보존 → 선택 재처리.
   DLT 발행 실패를 복구 성공으로 처리하지 않고 중복 결과·알림의 멱등성을 유지.

현재 outbox 기본값: PENDING / IN_FLIGHT / SENT, polling 500ms, 리스 60초,
재시도 간격 5초부터 최대 60초, 선점 token으로 이전 소유자의 늦은 상태 갱신 거부.
Kafka 전송 대기 중 DB 트랜잭션을 유지하지 않는다.
SENT는 Kafka 발행 성공이며 AI 업무 처리 완료와 별개다.

결과 오류 처리기는 재시도 대상에 최초 처리 후 1초 간격 최대 2회 재시도한다.
잘못된 입력은 재시도 대상에서 제외하고 ai-result-topic.DLT / log-topic.DLT에 보존한다.
DLT 전송 실패 시 원본 offset이 조용히 전진하지 않도록 처리한다.
실제 기본값은 관련 코드·application.yml에서 다시 확인한다.

[코드·SQL 진입점]

Java 기준 경로:
C:/Projects/2026_kw_capstone_project/backend/src/main/java/com/example/security_log_system/

- service: LogService, AiRequestOutboxService, AiRequestOutboxPublisher,
  AiRequestOutboxDispatcher, ThreatService, PipelineTrace, RequestAlertPublisher.
- repository: AiRequestOutboxRepository.
- kafka: AiRequestProducer, AiResultConsumer, LogKafkaConsumer.
- config: KafkaProducerConfig, KafkaConsumerConfig, PipelineKafkaErrorConfig, OutboxSchedulingConfig.
- DB SQL: C:/Projects/2026_kw_capstone_project/docs/db/add-ai-request-outbox.sql

ddl-auto: validate이므로 SQL 자동 적용을 가정하지 않는다.
로컬 outbox 동작은 과거 실측으로 확인했지만 EC2 SQL 적용·배포 여부는 별도 확인 대상이다.
운영 DB에는 대상·현재 구조·백업·배포 순서를 확인한 뒤 필요한 변경만 적용한다.

[완료한 복구 검증과 범위]

격리 복구 r02: 20261103T181230+0900-local-recovery-r02 → PASS.
실제 별도 MySQL 스키마·embedded Kafka·테스트 전용 JVM에서 다음을 확인했다.

1. 로그·outbox 동시 롤백과 미커밋 작업 선점 불가.
2. 커밋 후 발행·실제 Kafka ACK·SENT 기록.
3. TCP 접속 실패 후 PENDING 보존·접속 복구 후 재전송.
4. 발행 전 JVM 종료 후 새 JVM의 작업 복구.
5. 선점 직후 종료 후 실제 60초 리스 만료·token 검증·복구.
6. ACK 후 SENT 기록 전 종료로 브로커 메시지 2건이 생겨도
   중복 결과 처리 후 탐지 1건·알림 revision 1·전송 대역 호출 1회 유지.
7. DLT 발행 실패 중 원본 offset 유지, 복구 후 DLT 보존·offset 진행.

당시 백엔드 35개(통합 7 + 단위 28), 프론트 hook 3개, 실행기 안전장치 3개가 통과했다.
이는 2026/11/03 실행 결과이며 이번 전달문 갱신에서 다시 실행한 결과가 아니다.

TCP 장애는 테스트 producer 경로, 재시작은 테스트 전용 JVM에 주입했다.
기존 Kafka/backend 컨테이너 자체를 중단한 검증은 아니다.
중복 결과는 고정 DTO이고 WebSocket 전송은 대역이었다.
실제 장애 중 브라우저 복구·동시 중복 스트레스·WAF 도착 순서 역전은 미검증이다.

근거:
C:/Projects/2026_kw_capstone_project/docs/testing/local/evidence/20261103-outbox-recovery-verification.json

[보완 후 실제 브라우저 E2E 결과]

공통: 회차별 워밍업 30초 제외, 측정 120초.
일반 요청과 10초당 탐지 probe 1건을 합친 총 요청률이다.
계획 건수와 실제 도착 수는 실행 끝 경계에서 다를 수 있으므로 실제 전송 수를 대조한다.

1RPS 정식 반복:

- r16: 20261103T182623+0900-local-e2e-rps1-r16, HTTP / DB / AI 완료 각 120, PASS.
- r17: 20261103T183007+0900-local-e2e-rps1-r17, 각 121, PASS.
- r18: 20261103T183545+0900-local-e2e-rps1-r18, 각 120, PASS.
- 세 회차·단계 PASS. HTTP·DB·AI 완료·outbox SENT 각 361건.
- probe 36건 모두 AI·WAF 수신·DOM, 대표 위협 행 확인. 관측 누락·중복 0.
- 일반 HTTP p95 6.857ms, AI 서버 p95 893.302ms, AI 알림 DOM p95 1657.601ms.

추가 3·5RPS는 각각 한 회차의 예비 확인이다.

| 항목 | 3RPS r21 | 5RPS r22 |
| --- | --- | --- |
| 실험 ID | 20261103T204036+0900-local-e2e-rps3-r21 | 20261103T204357+0900-local-e2e-rps5-r22 |
| HTTP / DB / AI 완료 / outbox SENT | 361 / 361 / 361 / 361 | 600 / 600 / 600 / 600 |
| probe / AI·WAF 출처별 수신·DOM | 12 / 각 12 | 12 / 각 12 |
| 일반 HTTP 표본 / p95 | 349 / 5.304ms | 588 / 5.564ms |
| 요청 → AI 커밋 p95 | 918.801ms | 891.940ms |
| 요청 → WAF 커밋 p95 | 396.718ms | 260.846ms |
| probe → AI 알림 DOM p95 | 1440.963ms | 1068.155ms |
| probe → WAF 알림 DOM p95 | 1380.474ms | 1065.936ms |
| AI 요청 경로 관측 최대 lag | 14 | 22 |
| 호스트 여유 메모리 관측 최저 | 약 1.25GiB | 약 1.77GiB |
| 회차 판정 | PASS | PASS |

두 회차 모두 측정 outbox 미완료 0, 최종 필수 consumer group lag 0을 두 번 연속 확인했다.
3·5RPS 각 1회 PASS를 3회 반복 단계 통과·최대 처리량으로 표현하지 않는다.
서로 다른 요청률의 지연 표본을 합치거나 회차별 p99를 평균내지 않는다.
probe 12건·36건의 p99는 참고값이다.

최초 예비 r19(20261103T203223+0900-local-e2e-rps3-r19)는 Docker 재기동 후
1RPS 워밍업 중 호스트 여유 메모리 약 0.71GiB, 1GiB 미만 15초 조건으로 INCONCLUSIVE였다.
실제 3RPS 측정·5RPS 실행은 없었다. 준비 요청 24건은 사후 모두 저장·AI 완료·SENT를 확인했다.
메모리 회복 후 새 r21·r22로 재시도했고 기존 중단 기준을 완화하지 않았다.
성공 회차와 초기 중단 기록을 모두 보존했다.

결과 해석:

- r15의 미완료는 보완 후 세 1RPS 회차와 추가 예비 회차에서 재현되지 않았다.
- outbox 보완은 정합성 개선이다. 개선 전 r14 AI 서버 p95 약 573ms보다
  보완 후 1RPS 약 871~904ms로 높게 관측됐으며 속도 개선으로 발표하지 않는다.
- polling 지연은 가설이며 실제 비용·DB 병목은 분리 검증하지 않았다.
- 3·5RPS의 지연 차이는 단일 회차·캐시·기동·DB 규모·호스트 메모리 영향도 있어 개선율로 계산하지 않는다.
- 종료 lag 0과 처리 완료 수를 함께 본다. lag만으로 업무 완료를 판정하지 않는다.
- 모든 장애의 누락 0·종단 exactly-once·EC2 성능을 보장하지 않는다.

결과·증거:
C:/Projects/2026_kw_capstone_project/docs/testing/local/runs/20261103-local-e2e-rps1-after-outbox-stage.md
C:/Projects/2026_kw_capstone_project/docs/testing/local/runs/20261103T204004+0900-local-e2e-prechecks-r21.md
C:/Projects/2026_kw_capstone_project/docs/testing/local/evidence/20261103-e2e-rps1-remeasurement.json
C:/Projects/2026_kw_capstone_project/docs/testing/local/evidence/20261103-local-prechecks-verification.json
C:/Projects/2026_kw_capstone_project/docs/testing/local/evidence/20261103-local-prechecks-memory-stop.json

[실행기·계측·인증 현황]

C:/Projects/2026_kw_capstone_project/scripts/testing/ 아래:
- run_e2e.py / e2e_core.py / browser_trace.js / summarize_e2e.py / guard.py
- run_recovery_verification.py
- run_local_prechecks.py / local_browser_login.py / test_local_browser_login.py

기존 실행기는 로컬 전용이다. localhost·127.0.0.1, Host localhost,
로컬 Compose의 DB·trace·lag·자원 수집과 시계 확인을 가정한다.
주소 제한만 풀어 EC2에 실행하지 않는다. 대상 검증·원격 수집·HTTPS·인증·시계를 별도로 연결해야 한다.

기본 run_e2e.py는 매 회차 실제 관리자 브라우저에 직접 로그인한다.
추가 보조 실행기는 명시적으로 허용받은 로컬 계정을 숨김 표준 입력으로 받아 메모리에만 보관하고
http://localhost:3000 또는 http://127.0.0.1:3000의 실제 로그인 폼에 입력한다.
실제 세션·CSRF·STOMP 준비를 기다리며 인증을 우회하지 않는다.
자동 로그인 검증 4개와 r21·r22 실제 로그인은 통과했다.
자격 증명·쿠키·storage state·민감한 예외 원문은 파일에 보존하지 않는다.
이 전달문에는 계정·비밀번호가 없다. EC2 인증 정보와 실행 허용 범위는 별도로 확인한다.

계측은 서버 requestId·밀리초 시작 epoch·run/phase/kind/sequence·logId·alertId를 연결한다.
DG_TRACE 단계는 LOG_COMMITTED / AI_RESULT_COMMITTED / WAF_COMMITTED /
ALERT_SEND_BEGIN / ALERT_SEND_RETURNED다. 전송 메서드 반환과 실제 브라우저 수신은 다르다.
HTTP·로그 적재·AI 처리·WAF 커밋·브라우저 수신·DOM 지연을 구분하고
평균·p50·p95·p99·최대·표본 수·미확인 수·lag·자원 추이를 남긴다.

로컬 DB DATETIME 해석 문제는 별도 증거가 있고 현재 정밀 지연은 UTC DG_TRACE와 WAF epoch를 사용한다.
DB에 임의로 9시간을 더하거나 전역 시간대를 바꾸지 않는다. EC2 시계·저장 시각은 새로 확인한다.

[EC2 준비에서 확인할 것]

기존 서비스 주소 후보이며 현재 접속·배포 상태는 확인 필요:
- 대시보드: https://security-monitor-kw.duckdns.org/
- 부하 대상 JuiceShop: https://security-juiceshop-kw.duckdns.org/

우선 확인·준비할 항목:
1. outbox·Consumer·계측 변경의 배포 여부, 운영 DB 추가 SQL 적용 여부.
2. 실제 앱 SHA·이미지 digest·WAF 설정·모델·DB 규모·초기 lag.
3. 인스턴스 사양·자원 한도·T3라면 CPU 크레딧과 모드.
4. 서버와 분리한 발생기, 팀원 사용 시간과 겹치지 않는 측정 구간.
5. DB 읽기 전용 조회·backend trace·Kafka lag·컨테이너 자원의 원격 수집 경로.
6. 실제 관리자 브라우저의 인증·알림 수신·DOM 관측.
7. 서버 requestId·계측 헤더의 HTTPS 프록시 통과와 시계·오차 확인.
8. 발생기 IP의 실제 WAF 차단·제외 상태와 정책상 부하 조건.
9. 쿼리·커넥션·락·outbox 적체를 관측할 최소 지표와 수집 비용.
10. EC2 소량 연결 검증, 목표·중단·복구 기준, 본 실험의 반복 수·기간·부하 상한.

테스트 IP가 자동 차단되면 빠른 403만 측정할 수 있다. 정책 변경이 필요하면 적용 범위·영향을 먼저 정한다.
로컬 게이트웨이 제외를 외부 EC2 클라이언트에도 그대로 적용할 수 있다고 가정하지 않는다.
기존 배포 흐름은 기능 PR → develop → main 릴리스 PR → main의 수동 Actions 실행이며
머지만으로 배포됐다고 판단하지 않는다. 최신 워크플로·배포 스크립트를 확인한다.

[기록과 이번 요청 범위]

- 실험 전 목표·합격·중단·복구 기준을 정한다. 결과를 보고 소급 완화하지 않는다.
- Situation / Task / Target / Action / Result / Trouble을 기록한다.
- 사람용 날짜는 YYYY/MM/DD, 시각은 한국 시간. 원본 ISO 시각과 경로용 ID는 보존한다.
- 실패·중단·INCONCLUSIVE도 보존하고 재실행은 새 ID를 사용한다.
- 원본·공유 증거의 과거 해시·판정을 현재 코드 기준으로 덮어쓰지 않는다.
- 비밀값을 출력하지 않고 down -v·prune·운영 DB/offset 초기화를 일반 해결책으로 쓰지 않는다.
- 문서·모의 검증·격리 통합·실제 서비스 부하·운영 반영을 구분해 보고한다.

먼저 문서와 필요한 코드를 읽고 아래를 보고해줘.
1. 현재 브랜치·변경 상태와 완료/미완료 범위가 위 기록과 맞는지.
2. EC2에 재사용할 계측과 최소 변경이 필요한 실행·수집·인증 경로.
3. EC2 준비 작업의 구체적 순서·각 완료 기준·미확정 접근 정보.
4. DB 부하 관측을 포함한 다음 구현 범위와 검증 방법.

이번 첫 단계는 준비 상태·구현 범위 확인이다. 실제 운영 부하·서비스 중단·배포·DB 변경을
처음부터 실행하지 말고, 위 확인 결과를 바탕으로 다음 작업을 구체화해줘.
