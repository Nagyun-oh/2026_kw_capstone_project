# EC2 테스트 · 병목 개선 · 동일 조건 재측정

최종 갱신: **2026/11/07**

[공통 가이드](../README.md) · [로컬 테스트](../local/README.md) · [AWS 배포](../../operations/aws_deployment.md)

EC2에서는 실제 배포 환경의 별도 기준선을 측정하고, 확인된 병목·결함 개선 후 같은 EC2 조건에서 다시 측정한다. **P0·P1·P3~P8 및 정식 1·3·5 RPS 기준선 완료. 각 단계는 120초·3회 모두 PASS다.** [P0](P0.md)는 현황 조회, [P3](P3.md)는 환경 분리, [P4](P4.md)는 원격 수집, [P5](P5.md)는 시계·자원 감시, [P6](P6.md)는 DB 전후 관측, [P7](P7.md)는 인증·소량 연결, [P8](P8.md)는 확정 기준·전체 실행·원복을 다룬다. [1 RPS](runs/20261105-ec2-1rps-baseline-review.md) · [3 RPS](runs/20261105-ec2-3rps-baseline-review.md) · [5 RPS](runs/20261106-ec2-5rps-baseline-review.md) · [세 단계 비교](runs/20261106-ec2-1-3-5rps-comparison.md). 다음은 구간별 지연·완료 EPS·lag·자원 분석이다. 최대 처리량·knee point는 미확정이며 추가 부하 상한은 별도로 정한다. EC2 전용 실행기는 `run_ec2_e2e.py`이며 기존 로컬 실행기의 EC2 실행 경로는 계속 차단한다.

조사할 문제·계층·해결책은 실제 관측에서 정한다. DB 조회·집계·페이지 처리·락·커넥션, AI 처리, Kafka·수집·알림 등 어떤 구간이든 근거가 있으면 조사하며 정해진 사례 수를 채우지 않는다. API 조회를 측정한다면 해당 API의 응답·쿼리·자원·정확성을, 파이프라인을 측정한다면 처리 완료·적체·알림 등 그 범위에 맞는 지표를 선택한다.

회차별 기록은 공통 실험 양식으로 남긴다. 트러블슈팅 사례는 두 템플릿을 복사해 요약본과 상세본으로 작성한다. 원인 미확정·개선 효과 없음도 결과로 보존한다. [요약 템플릿](<보고서양식1(핵심 요약).md>) · [상세 템플릿](<보고서양식2(자세한 해결과정).md>)

## 진행 단계

| 순서 | 작업 | 상태 | 완료 기준·다음 작업 |
| --- | --- | --- | --- |
| 1 | EC2 측정 환경·실행 도구 준비 | 완료 — P8 실제 전체 실행·원복 PASS | 입력 선보관·자동 로그인·원격 수집·감시·DB 관측·판정·원복 연결 확인. 전체 회귀 252개 통과 |
| 2 | EC2 저부하 예비 측정·목표 확정 | 완료 — 1 RPS·60초 pilot r03 PASS | 측정 60건·DB 60건·AI 완료 60건·probe 6건. AI/WAF 서버 p95 약 997/569ms. 예비 결과는 정식 기준선과 분리 |
| 3 | EC2 기준 측정·단계적 부하 | 완료 — 1·3·5 RPS 각 3/3 PASS, 단계 부하로 지연 knee 11~13 RPS 확인(2026/11/08 성능 부하 테스트 종료) | 총 3,240건 저장·AI 완료. [세 단계 비교](runs/20261106-ec2-1-3-5rps-comparison.md). 5 RPS는 시각 검증 계측 버전 차이 명시. 추가 부하·한계점 탐색은 미실행. 2026/11/08 계약 개정 4(단계 모드 7·9·11·13 RPS, 한계 신호 계산, 원복 전 정리 300초) 실행기 구현·회귀 276개 통과(미커밋). 단계 7·9·11 RPS 각 1회 PASS·한계 신호 없음. **13 RPS에서 첫 한계 신호**(서버 p95 AI 3,128.8ms, 호스트 CPU 89.5%)로 knee는 11~13 RPS다. 처리량은 유지되고 AI 구간 대기열이 교란마다 수 초씩 쌓이는 모양이며, 측정 도구(lag CLI 중복 실행)가 신호를 키웠다(제외해도 p95 2,698ms). [단계 부하 결과](step-load-plan.md). 실행기 보완(lag 시도 시각 기록·DB 실패 분류 코드, 회귀 279개) 완료. 정식 반복 첫 회차 11 RPS r02는 INCONCLUSIVE로 중단됐다. 실행기 DB 수집 쿼리가 `network_logs` 전체 JSON 스캔이라 데이터가 쌓일수록 느려져 3초 제한(`3024`)에 걸렸고, 같은 11 RPS의 p95도 586 → 2,030ms로 재현되지 않았다. 측정 도구 부담을 줄이려고 계약 개정 5(부하 중 lag CLI 끔)와 DB 수집 쿼리 보완(시작 전 최대 로그 id 하한·인덱스 조인, DB 실행 약 1,640 → 24ms)을 마쳤다(회귀 282개). 재측정 1차: 5 RPS r36 PASS, **호스트 CPU 58.0 → 47.1%**(측정 도구가 부하 CPU의 약 1/5을 쓰고 있었음), 서버 p95 AI 268.5ms(1회 참고). 11 RPS r03은 k6 요청 2건의 교차 시계 0.2~1.9ms 불일치로 규칙대로 중단(INCONCLUSIVE, 원복 확인, 서버 지연 판정과 무관). 계약 개정 6(k6 일반 요청 교차 시계 불일치는 진단 기록, probe·보정 만료는 계속 중단, 회귀 287개) 완료. **11·13 RPS 각 3/3 PASS·한계 신호 없음**: 서버 p95 AI 합산 852ms / 2,040ms, 호스트 CPU 약 74% / 81%. 앞선 13 RPS 한계 신호는 측정 도구 부담 때문이었다. 지연 곡선은 11~13 RPS에서 꺾이고, SLO 처리 한계는 13 RPS 위(미측정)다. [4-5절](step-load-plan.md) |
| 4 | 장애·정합성 검증 | 시작 전 | 영향 범위를 정하고 한 종류씩 장애를 검증. 복구·누락·중복·DLT·알림 상태 대조 |
| 5 | 확인된 병목·결함 개선 | 알림·AI outbox 250ms 비교 완료 및 EC2 운영 적용 · 로그 목록 인덱스 EC2 적용 | 알림 발행 지연과 DB 조회 비용 대조, AI outbox 발행 평균 300.9 → 163.7ms. 대시보드 로그 목록 127.7 → 0.7ms(부하 중). [트러블슈팅_1](<트러블슈팅_1(상세본).md>) · [트러블슈팅_2](<트러블슈팅_2(상세본).md>) · [트러블슈팅_3](<트러블슈팅_3(상세본).md>) |
| 6 | 동일 조건 재측정·비교 | 알림·AI outbox 설정, 로그 목록 인덱스 비교 완료 | 같은 5 RPS·120초 조건에서 각 세 회차 PASS. 호스트 상태 변화와 중단 회차는 별도 기록 |

부하 측정과 장애 주입은 서로 다른 회차로 분리한다. 로컬에서 검증한 복구 절차를 EC2 환경에 맞게 확인하며, 운영 서비스의 중단·변경을 문서 작업의 일부로 수행하지 않는다.

## EC2에서 별도로 고정할 조건

| 조건 | 기록할 내용 |
| --- | --- |
| 대상 | 배포 앱 SHA·이미지 digest, WAF 설정, 모델·탐지 정책, DB 규모·초기 lag |
| 서버 자원 | 인스턴스 유형·vCPU·메모리·스토리지, Docker 한도, T3 계열이면 CPU 크레딧 잔량·모드 |
| 부하 발생기·경로 | 가능하면 대상 서버와 분리한 발생기, 사양·위치, HTTPS→EC2 Nginx→WAF→JuiceShop 경로 |
| 처리·차단 조건 | 테스트 IP 등록·차단 제외 여부, 정상 부하와 예상한 403의 집계 구분, 발생한 위협 저장·알림 부하 |
| 수집·복구 | HTTP 평균·p50·p95·p99·최대값과 건수·기간, 비동기 지연·연속 lag·자원, 최종 대기·중단·복구 기준. p50은 참고 지표 |
| 비교 조건 | 입력·요청률·시간·준비 요청·캐시·반복 수·수집 방식, 동시 사용·배포 여부 |

계측과 목표를 먼저 확정하고 실행 도구의 EC2 지원을 별도로 구현·검증한다. 임의로 로컬 주소 제한만 해제해 실행하지 않는다. 준비 상태와 실제 실행 여부는 구분해서 기록한다.

## 준비 상태 확인 (2026/11/05)

로컬 앱 작업 기준은 `d6ec7c4b`이며 outbox·Consumer 복구·계측·기존 실험 도구는 커밋된 상태다. 이번 P0 수집기·문서는 작업 트리 변경으로 추가했다. **실제 EC2 HEAD는 `e50029b18424e829da4f9d2236b131fb5fe0b0b5`이며 앱 이미지 3개의 태그와 일치하고 `d6ec7c4b`를 포함한다.** [P0 보고서](runs/20261105T165534+0900-ec2-inventory-r03.md)와 [공유 증거](evidence/20261105-p0-inventory-review.json)를 기준으로 재개한다.

사용자가 제공한 2026/11/05 EC2 출력에서 내부 HTTPS 요청의 HTTP 200·계측 헤더, 같은 요청의 로그 커밋 → Kafka ACK → AI NORMAL 커밋, outbox `SENT / attempts=1 / last_error_code=NULL`을 확인했다. [증거 요약](evidence/20261105-deployment-smoke-user-provided.json)은 사용자 제공 출력의 전사이며 신규 자동 수집 결과가 아니다. 내부 loopback resolve로 호출했으므로 외부 DNS·발생기 경로·브라우저 알림까지 검증한 것으로 보지 않는다.

| 구분 | 확인한 사실 | 의미 |
| --- | --- | --- |
| 코드·배포 버전 | EC2 HEAD와 backend·frontend·ai 이미지 태그 일치, EC2 작업 트리 clean. 수집한 Compose·WAF·모델 lock 8개 파일 해시는 d6ec7c4b와 일치 | 이미지 ID·digest를 증거에 보존. 실제 모델 바이너리 무결성 검사는 별도 |
| DB | 핵심 테이블 8개·필수 UNIQUE·request_id 이진 collation·request_url TEXT·outbox FK 확인. 17:00:57 KST 기준 전체 로그 7,586건·탐지 239건·블랙리스트 0건·outbox SENT 1건 | 추정 행 수와 별도 제한 시간 내 정확한 건수 조회를 구분. 과거 로그 전체의 분석 완료를 증명하는 값은 아님 |
| WAF 반영 | 활성 설정·내부 HTTPS 출력 보존, P7에서 실제 외부 HTTPS 요청·두 출처 알림 수신/DOM·대표 위협 행까지 확인 | 소량 연결 확인이며 성능·부하 합격을 의미하지 않음 |
| 환경 변수·계정 | 실행 중 backend의 outbox·trace·WAF Consumer 모두 true. DB 조회는 컨테이너 앱 계정으로 성공 | 키 존재 여부만 기록하고 비밀번호는 출력하지 않음. root·관리자 비밀번호 변경 여부는 확인 범위 밖 |
| 서비스·자원 | 상시 서비스 9개 running, init는 종료 코드 0. t3.large·2 vCPU, 여유 메모리 4.78GiB·디스크 27.39GiB, 필수 consumer group lag 모두 0, NTP 동기화 확인 | 단일 시점 현황이다. 부하 수용량·업무 처리 완료·성능 합격으로 해석하지 않음 |
| CPU 크레딧 | 모드 unlimited는 사용자 콘솔 확인, 잔량 864는 사용자 툴팁 사진의 2026/11/05 07:50 UTC(16:50 KST) 관측값 | 서버 API 조회 권한 거부는 원본에 보존. 권한을 추가하지 않았으며 실제 부하 직전·종료 후에도 시각과 값을 기록 |
| 차단 정책 | P7에서 HTTPS 실제 로그 IP와 SSH 출구 IP를 대조한 뒤 단일 IP 임시 제외·시험 등록·제외 보고 확인 | 시험 등록 삭제·원래 제외 목록 복구·HTTP 200 확인 완료. 현재 임시 제외를 유지 중인 상태가 아님 |
| 시계 | 로컬 ±100ms 규칙은 유지하고 P5에서 EC2용 4시각 교환·오프셋 구간을 구현. 실제 r01 서버−PC는 약 +329~335ms | 서버 구간과 PC 브라우저 구간을 분리한다. 보정은 회차마다 확보하며 이 관측값을 영구 상수로 사용하지 않음 |

### 준비 순서와 완료 기준

| 순서 | 작업 | 완료 기준 | 상태 |
| --- | --- | --- | --- |
| P0 | EC2 읽기 전용 현황 수집 | 배포 SHA·EC2 작업 트리 상태·이미지 digest, `.env.aws` 키 존재 여부(값 제외), 테이블·UNIQUE 구조, 데이터 규모, consumer group lag, chrony 오차, 인스턴스·크레딧 모드, 메모리·디스크, 로그 드라이버, 호스트 Nginx 헤더 설정을 비밀값 없는 증거 JSON으로 기록 | 완료 — [r03 보고서](runs/20261105T165534+0900-ec2-inventory-r03.md). API 조회 불가 크레딧은 콘솔 자료로 보완. 실제 성능은 미평가 |
| P1 | 실행 조건 결정 | 접근 방식, 발생기 위치·공인 IP, 발생기 IP 차단 정책, 측정 시간대, 관리자 로그인 방식, 배포 일정 확정 | 완료 — [확정 조건](P1.md). 현재 PC 발생·브라우저 / IP 하나 임시 제외 / 준비 후 즉시·팀원 미사용. 실제 제외·부하 실행은 아직 미수행 |
| P2 | 배포·변경 이력 확인 | PR → develop → main → 수동 Actions 배포, SQL 사전 적용·백업·env·WAF 반영·검증·롤백 근거 확인 | 배포 SHA·이미지·DB·WAF 반영 현황 확인. 절차는 [AWS 배포](../../operations/aws_deployment.md)·[CI/CD](../../operations/cicd.md) 참조. 삭제된 별도 절차서는 복원하지 않음. 과거 백업 수행 여부는 별도 미확인 |
| P3 | 실행기 환경 분리 | `local`/`ec2` 프로필로 대상 URL 허용 목록·HTTPS 검증·보고서 경로·실험 ID 접두사 분리. 기존 로컬 모의 테스트 회귀 통과 | 완료 — [P3 가이드](P3.md). Python 144개 통과·k6 초기화 확인. EC2는 dry-run만 지원, 실제 부하 없음 |
| P4 | 원격 수집 어댑터 | 기존 lag·DB·DG_TRACE·컨테이너 파서를 원격 명령으로 재사용하고 EC2 쪽에서 로그를 필터링. 명령 시간·실패를 기록하고 부하 없이 수집만 성공 | 완료 — [P4 가이드](P4.md)·[r02 보고서](runs/20261105T182244+0900-ec2-collection-r02.md). 167개 모의 회귀·실제 2표본 수집 성공. 성능 미평가 |
| P5 | 시계·가드 | 여러 보정 요청으로 발생기 시계 오프셋 구간을 기록. 발생기와 EC2 호스트 자원(메모리·CPU steal·가능하면 크레딧)을 따로 감시 | 완료 — [P5 가이드](P5.md). 실제 5회 시각 교환·5자원 표본, 전체 186개 회귀 통과. 최신 크레딧은 미수집. 성능 미평가 |
| P6 | DB 관측 | 측정 전후 statement digest 차이, 전역 상태, 락 대기·장기 트랜잭션, outbox 상태·대기·발행 지연(DB 시계), 테이블 크기를 읽기 전용으로 수집하고 수집 비용 기록 | 완료 — [P6 가이드](P6.md). 실제 전후 수집·비교 성공, 70개 digest·22개 전역 상태·8개 테이블 확보. 전체 210개 회귀 통과. 성능 미평가 |
| P7 | 인증·소량 연결 검증 | EC2 대시보드 직접 로그인 후 STOMP 준비, 정상 요청 헤더·로그 연결, probe 1건의 두 출처 수신·DOM 확인, 결정한 IP 정책대로 차단 상태 확인 | 완료 — [P7](P7.md). r03의 핵심 연결·원복 증거와 [대표 행 재확인 PASS](runs/20261105T205423+0900-ec2-table-recheck-r01.md)를 연결해 종결. r03 자체 INCONCLUSIVE는 보존 |
| P8 | EC2 목표·중단 기준 확정 | 소량 결과로 부하 상한·반복·중단·복구 기준을 실행 전에 확정. 로컬 기준을 그대로 복사하지 않음 | 완료 — [P8](P8.md). 고정 계약 개정 2, 전체 회귀 252개·안내 경로 16개 추가 확인, 실제 pilot r03 PASS·원복 후 대조 완료. [검토](runs/20261105-p8-review.md) |

## 실험 기록

준비·예비 측정과 정식 기준선을 구분한다. 접근 실패·계측 중단·다른 계측 버전의 회차도 원본 판정 그대로 보존한다.

| 날짜 | 단계·시나리오 | EC2 보고서·ID | 판정·범위 |
| --- | --- | --- | --- |
| 2026/11/05 | P0 수집 준비·SSH 접근 확인 | [ec2-inventory-r01](runs/20261105T163246+0900-ec2-inventory-r01.md) | INCONCLUSIVE — SSH 시간 초과, 실제 현황 미수집. 부하 발생 없음 |
| 2026/11/05 | P0 첫 원격 수집·수집기 보완 | [ec2-inventory-r02](runs/20261105T165207+0900-ec2-inventory-r02.md) | INCONCLUSIVE — healthcheck 없는 컨테이너 누락. 원본 보존 후 새 회차 재수집 |
| 2026/11/05 | P0 재수집·콘솔 보완 | [ec2-inventory-r03](runs/20261105T165534+0900-ec2-inventory-r03.md) | P0 현황 수집 완료. 크레딧 사용자 콘솔 증거 포함. 성능·부하 미평가 |
| 2026/11/05 | P1 실행 조건 합의·발생기 확인 | [ec2-execution-conditions-r01](runs/20261105T172253+0900-ec2-execution-conditions-r01.md) | 조건 합의 완료. 부하·임시 제외 미적용, 성능 미평가 |
| 2026/11/05 | P4 첫 읽기 전용 수집 | [ec2-collection-r01](runs/20261105T181809+0900-ec2-collection-r01.md) | 2표본 COLLECTED. 기존 요청 계측 필터 확인. 성능 미평가 |
| 2026/11/05 | P4 최종 수집기·HEAD 기록 | [ec2-collection-r02](runs/20261105T182244+0900-ec2-collection-r02.md) | 2표본 COLLECTED, 9개 running·필수 4개 경로 lag 0. [증거](evidence/20261105-p4-remote-collection.json). 성능 미평가 |
| 2026/11/05 | P5 시계·자원 읽기 전용 관측 | [ec2-watch-r01](runs/20261105T190322+0900-ec2-watch-r01.md) | COLLECTED. 서버−PC 약 +329~335ms, 관측 중 중단 사유 없음. [증거](evidence/20261105-p5-clock-resource-guards.json). 성능 미평가 |
| 2026/11/05 | P6 첫 DB 전후 수집 | [ec2-db-observation-r01](runs/20261105T192232+0900-ec2-db-observation-r01.md) | INCOMPLETE. 전역 상태·outbox·크기 조회 성공, 통계·락·트랜잭션은 미확인 |
| 2026/11/05 | P6 인증·권한 오류 번호 확인 | [ec2-db-observation-r02](runs/20261105T192413+0900-ec2-db-observation-r02.md) | INCOMPLETE. 앱 1142·1227, 컨테이너 root 1045. 원본 유지 |
| 2026/11/05 | P6 숨김 입력·실제 전체 수집 | [ec2-db-observation-r03](runs/20261105T192941+0900-ec2-db-observation-r03.md) | COLLECTED·COMPARABLE. 사용자 직접 숨김 입력 후 결과 검토. [증거](evidence/20261105-p6-database-observation.json). 성능 미평가 |
| 2026/11/05 | P7 첫 시계 사전 검사 | [ec2-connection-r01](runs/20261105T195438+0900-ec2-connection-r01.md) | INCONCLUSIVE. 요청 0건·설정 변경 없음. 시계 단계 오류 상세 미보존 |
| 2026/11/05 | P7 시계 사전 검사 기록 | [ec2-connection-r02](runs/20261105T195514+0900-ec2-connection-r02.md) | INCONCLUSIVE. Windows 기본 시각과 단조 시계 차이 검출. 요청·설정 변경 전 중단, 정밀 UTC API로 보완 |
| 2026/11/05 | P7 실제 로그인·소량 연결·원복 | [ec2-connection-r03](runs/20261105T195628+0900-ec2-connection-r03.md) | 핵심 4건 저장·AI 완료·probe 두 출처 수신/DOM 확인, 복구 1건 포함 최종 5건 완료. 원복 확인. 추가 대표 행 관측 오류로 전체 INCONCLUSIVE. [검토·남은 항목](runs/20261105-p7-review.md) · [증거](evidence/20261105-p7-connection-review.json) |
| 2026/11/05 | P7 기존 대표 위협 행 재확인·종결 | [ec2-table-recheck-r01](runs/20261105T205423+0900-ec2-table-recheck-r01.md) | PASS. 위협 681·로그 8265·WAF 681·AI 682의 단일 그룹 행과 상세 버튼 확인. 새 probe·차단 변경 없음. [P7 완료 증거](evidence/20261105-p7-completion.json) |
| 2026/11/05 | P8 첫 예비 시계 검사 | [ec2-pilot-r01](runs/20261105T213711+0900-ec2-pilot-r01.md) | INCONCLUSIVE. 부하 0건·WAF 변경 없음. 불필요한 교차 시계 폭 중단 조건을 개정 2에서 진단 정보로 분리. 원본 유지 |
| 2026/11/05 | P8 전체 연결·송신 경계 검토 | [ec2-pilot-r02](runs/20261105T214342+0900-ec2-pilot-r02.md) | INCONCLUSIVE. 예정 60건 대신 61건 송신, 모두 저장·AI 완료·원복. 종료 경계 송신 상한을 보완. [두 회차 증거](evidence/20261105-p8-preliminary-attempts.json) |
| 2026/11/05 | P8 예비 측정·전체 실행·원복 | [ec2-pilot-r03](runs/20261105T215318+0900-ec2-pilot-r03.md) | PASS. 60건 저장·AI 완료·probe 6건 두 출처 알림·대표 행·DB 전후 비교 확인. 최종 lag 0·9서비스 정상·원래 설정 복구. [완료 증거](evidence/20261105-p8-completion.json) |
| 2026/11/05 | 정식 1 RPS·120초·3회 기준선 | [세 회차 검토](runs/20261105-ec2-1rps-baseline-review.md) · [원본 표본 합산](runs/20261105-ec2-1rps-baseline-summary.md) | 3/3 PASS. 측정 360건 저장·AI 완료·probe 36건. 서버 합산 p95 AI 1,004ms/WAF 608ms, 설정·차단 목록 복구·lag 0·9서비스 정상. [완료 증거](evidence/20261105-ec2-1rps-baseline-completion.json) |
| 2026/11/05 | 3 RPS 사전 DB 인증 | [ec2-e2e-rps3-r01](runs/20261105T224809+0900-ec2-e2e-rps3-r01.md) | BLOCKED/INCONCLUSIVE. DB root 1045, 부하 0건·WAF 변경 없음. 원본 보존 후 인증을 재확인하고 새 회차 실행 |
| 2026/11/05 | 정식 3 RPS·120초·3회 기준선 | [세 회차 검토](runs/20261105-ec2-3rps-baseline-review.md) · [원본 표본 합산](runs/20261105-ec2-3rps-baseline-summary.md) | r02~r04 모두 PASS. 측정 1,080건 저장·AI 완료·probe 36건. 서버 합산 p95 AI 1,017ms/WAF 614ms, 원복·lag 0·9서비스 정상. [완료 증거](evidence/20261105-ec2-3rps-baseline-completion.json) |
| 2026/11/06 | 5 RPS 최초 시계 구간 중단 | [r01](runs/20261106T102055+0900-ec2-e2e-rps5-r01.md) | INCONCLUSIVE. 시각 상한 약 1.52ms 초과. 서버 493건 저장·AI 완료·원복 확인, 원본 보존. [진단](evidence/20261106-5rps-clock-interruption.json) |
| 2026/11/06 | 5 RPS 첫 계측 보완 버전 | [r02](runs/20261106T104116+0900-ec2-e2e-rps5-r02.md) · [r03](runs/20261106T104630+0900-ec2-e2e-rps5-r03.md) · [r04](runs/20261106T105144+0900-ec2-e2e-rps5-r04.md) | r02/r03 개별 PASS, r04 INCONCLUSIVE. 표시용 UTC 해상도를 점프로 오인한 구현을 보완. 새로운 정식 세 회차에 합산하지 않음. [875표본 재검증](evidence/20261106-5rps-precise-clock-replay.json) |
| 2026/11/06 | 정식 5 RPS·120초·3회 기준선 | [세 회차 검토](runs/20261106-ec2-5rps-baseline-review.md) · [합산](runs/20261106-ec2-5rps-baseline-summary.md) | 정밀 계측 버전 r05~r07 모두 PASS. 측정 1,800건 저장·AI 완료·probe 36건, 서버 합산 p95 AI 1,049ms/WAF 541ms. 원복 후 총 1,896건 완료·lag 0·9서비스 정상. [완료 증거](evidence/20261106-ec2-5rps-baseline-completion.json) |

## 병목·결함 개선과 재측정 연결

| 사례·시나리오 | EC2 기준선 보고서·ID | 관측 문제·원인 근거 | 개선 변경 SHA·설정 | 동일 조건 재측정 보고서·ID | 판정·비교 제한 |
| --- | --- | --- | --- | --- | --- |
| 알림 발행 지연 | [5 RPS r05~r07](runs/20261106-ec2-5rps-baseline-review.md) | 1초 조회 대기, 커밋→전송 시작 p95 AI 867.5ms·WAF 974.7ms | [기존 이미지로 EC2 250ms 운영 적용](evidence/20261107-alert-poll-250ms-operating.json) | [r10](runs/20261107T134708+0900-ec2-e2e-rps5-r10.md) · [r12](runs/20261107T140040+0900-ec2-e2e-rps5-r12.md) · [r13](runs/20261107T140627+0900-ec2-e2e-rps5-r13.md) | 3/3 PASS. 250ms에서 AI 249.5ms·WAF 249.3ms. [상세 해결 과정](<트러블슈팅_1(상세본).md>) · [비교 증거](evidence/20261107-alert-poll-250ms-comparison.json) |
| AI 요청 outbox 발행 지연 | [5 RPS r10·r12·r13](<트러블슈팅_1(상세본).md>) | outbox 생성→발행 완료 기록 가중 평균 300.9ms, 관련 SQL 평균 1ms 미만. 500ms 조회 대기가 가설 | 기존 이미지에 `APP_AIOUTBOX_POLLDELAYMS=250` 임시 적용·500ms 원복 후 [EC2 250ms 운영 적용](evidence/20261107-ai-outbox-poll-250ms-operating.json). 알림 발행은 250ms 유지 | [r14](runs/20261107T143741+0900-ec2-e2e-rps5-r14.md) · [r15](runs/20261107T144314+0900-ec2-e2e-rps5-r15.md) · [r16](runs/20261107T144857+0900-ec2-e2e-rps5-r16.md) | 3/3 PASS. outbox 평균 163.7ms(45.6%↓), 로그→AI 결과 커밋 p95 754.8→526.3ms. 화면 표시는 36표본·공통 경로 변동 포함. [요약본](<트러블슈팅_2(요약본).md>) · [상세본](<트러블슈팅_2(상세본).md>) · [비교 증거](evidence/20261107-ai-outbox-poll-250ms-comparison.json) |
| 대시보드 로그 목록 전체 스캔 | [5 RPS r14~r16 DB 관측](<트러블슈팅_3(상세본).md>) | 최신 10건 조회가 평균 127.7ms·호출당 1.6만~1.8만 행 검사·인덱스 미사용. EC2 실행 계획 Table scan 18,199행 → Sort. `created_at` 인덱스 없음 | `network_logs(created_at)` 인덱스: 엔티티·새 DB 스키마·[기존 DB용 SQL](../../db/add-network-logs-created-at-index.sql). 격리 MySQL 검증 후 [2026/11/07 16:26 EC2 적용](evidence/20261107-network-logs-index-operating.json): 18,562행 스캔 45.7ms → 인덱스 10행 0.095ms(부하 없음) | [r17](runs/20261107T165926+0900-ec2-e2e-rps5-r17.md) · [r18](runs/20261107T170458+0900-ec2-e2e-rps5-r18.md) · [r19](runs/20261107T171013+0900-ec2-e2e-rps5-r19.md) · 3/3 PASS. 부하 중 로그 목록 평균 127.7 → 0.7ms, 호출당 검사 16,996 → 5.5행, INSERT 비용 증가 없음. AI 경로 p95 감소는 원인 미확인. [전후 비교](evidence/20261107-network-logs-index-comparison.json) | [요약본](<트러블슈팅_3(요약본).md>) · [상세본](<트러블슈팅_3(상세본).md>) · [실행 계획](evidence/20261107-dashboard-query-explain.json) · [적용 전 검증](evidence/20261107-network-logs-index-preapply-verification.json) |
| 로그 수집 Flush 대기 | [5 RPS r17~r19](<트러블슈팅_4(상세본).md>) | WAF 접수 → 로그 커밋 1,800건이 약 58~560ms에 고르게 분포(평균 313.7ms, p95 521.8ms). Fluent Bit `Flush 0.5`초 주기 대기가 가설 | Flush 0.5 → 0.1, [2026/11/07 17:36 EC2 적용](evidence/20261107-fluentbit-flush-operating.json)(호스트 설정 사본 + 운영 오버라이드로 먼저 적용, 이후 저장소 설정 0.1을 `d45960f2`로 배포) | [r21](runs/20261107T175904+0900-ec2-e2e-rps5-r21.md) · [r22](runs/20261107T180436+0900-ec2-e2e-rps5-r22.md) · [r23](runs/20261107T181012+0900-ec2-e2e-rps5-r23.md) (r20 INCONCLUSIVE: 대표 행 화면 확인 시간 초과, 보존·제외) | 3/3 PASS. 로그 커밋 p95 521.8 → 165.3ms, AI 알림 표시 p95 1,268 → 1,133ms(평균 1,000 → 783ms), WAF 알림 p95 901 → 622ms. 운영 유지, 저장소 설정 0.1 배포(`d45960f2`). [비교 증거](evidence/20261107-fluentbit-flush-comparison.json) · [요약본](<트러블슈팅_4(요약본).md>) · [상세본](<트러블슈팅_4(상세본).md>) |
| 발행기 조회 대기(커밋 직후 깨우기) | [5 RPS r21~r23](<트러블슈팅_5(상세본).md>) | 탐지 커밋 → 알림 전송 시작 p95 AI 226.5ms·WAF 232.0ms, AI outbox 발행 평균 152.0ms. 250ms 주기 대기 모양 | 커밋 후 발행기 깨우기 + 주기 조회는 복구용 유지(PR #110, `d45960f2` 배포). 끄기 플래그 `APP_*_WAKEUPENABLED` | 같은 이미지 끔 [r24](runs/20261107T200524+0900-ec2-e2e-rps5-r24.md)~[r26](runs/20261107T201616+0900-ec2-e2e-rps5-r26.md) / 켬 [r27](runs/20261107T202514+0900-ec2-e2e-rps5-r27.md)~[r29](runs/20261107T203607+0900-ec2-e2e-rps5-r29.md) | 6/6 PASS, 목표 3개 충족. 커밋 → 전송 시작 p95 AI 230.0 → 17.1ms, WAF 240.8 → 14.7ms, outbox 평균 160.4 → 35.8ms. 선점 조회 1.61배. 재생성 직후 첫 회차의 꼬리 지연은 판정 보류. [요약본](<트러블슈팅_5(요약본).md>) · [상세본](<트러블슈팅_5(상세본).md>) · [비교 증거](evidence/20261107-wakeup-after-commit-comparison.json) |
| 측정 도구 부담(lag 조회 CLI) | [5 RPS r17~r19·r21~r23](<트러블슈팅_6(상세본).md>) | Kafka CPU 평균 24.5~78.9%의 대부분이 실행기의 `kafka-consumer-groups` CLI(120초에 8회·회당 약 5초). 실행 중 Kafka 27.6~131.7%, 그 외 2.7~6.6%. 부담 중앙값 약 0.5 vCPU. CLI 실행 중 커밋된 요청의 로그 커밋 → AI 결과 커밋이 여섯 회차 모두 21~61ms 더 김 | 실행기에서 부하 중 lag 조회를 60초 간격으로 분리, 측정 계약 개정 3(앱 배포·EC2 변경 없음) | [r30](runs/20261107T215657+0900-ec2-e2e-rps5-r30.md)~[r32](runs/20261107T220805+0900-ec2-e2e-rps5-r32.md) (개정 3 새 기준선) | 부분 충족. lag 조회 8 → 2회, 호스트 CPU 74.4 → 63.8%. Kafka 평균 CPU는 23~36%로 목표 10% 미달이다. 남은 원인은 15초 healthcheck `kafka-topics` CLI이고, 처음 추정(약 0.5 vCPU)은 과대였다. 2026/11/08 유휴 측정에서 healthcheck가 상시 약 0.22 vCPU(서버 용량의 약 11%)로 확인됐다. [재측정 증거](evidence/20261107-measurement-overhead-rev3-comparison.json) · [유휴 기준 증거](evidence/20261108-idle-baseline-kafka-healthcheck.json) · [요약본](<트러블슈팅_6(요약본).md>) · [상세본](<트러블슈팅_6(상세본).md>) · [진단 증거](evidence/20261107-measurement-overhead-kafka-lag-cli.json) |
| Kafka healthcheck 상시 CPU | [유휴 3분 측정 2026/11/08](<트러블슈팅_7(상세본).md>) | `kafka-topics --list` healthcheck가 15초마다 JVM 기동(회당 2.85초·약 3.8 CPU초). 부하 없이도 약 0.22 vCPU(서버 용량의 약 11%, 유휴 CPU의 절반) | 간격 15 → 60초, 기동 중 5초 간격(`start_interval`), 시작 유예 120초, retries 12 → 3(unhealthy 판정 약 3분 유지). 확인 명령은 그대로. PR #112(`1b6d818c`)로 2026/11/08 11:06 배포 | 유휴 3분 재측정(11:17) | 목표 4개 충족. Kafka 유휴 평균 23.75 → 9.68%, 유휴 서버 0.42 → 0.28 vCPU, healthcheck 3분 12 → 3회, 기동 순서 정상. 5 RPS 기준선 [r33](runs/20261108T112814+0900-ec2-e2e-rps5-r33.md)~[r35](runs/20261108T113848+0900-ec2-e2e-rps5-r35.md) 3/3 PASS, 부하 중 서버 CPU 63.8 → 58.0%. 이후 5 RPS 기준선은 r33~r35. [재측정 증거](evidence/20261108-idle-after-kafka-healthcheck.json) · [기준선 비교](evidence/20261108-healthcheck-5rps-baseline-comparison.json) · [요약본](<트러블슈팅_7(요약본).md>) · [상세본](<트러블슈팅_7(상세본).md>) · [유휴 기준 증거](evidence/20261108-idle-baseline-kafka-healthcheck.json) |
| 단계 부하 측정 도구 부담(수집 쿼리 전체 스캔·부하 중 lag CLI) | 단계 [r01](runs/20261108T123035+0900-ec2-step-rps13-r01.md)(13 RPS FAIL p95 3,128.8ms)·[11 RPS r02](runs/20261108T125333+0900-ec2-step-rps11-r02.md)(INCONCLUSIVE, `3024`) | 실행기 DB 수집 쿼리가 `network_logs` 전체 JSON 해석 + 행마다 `waf_detections` 재탐색(DB 약 1,640ms, 데이터 누적에 비례). 부하 중 lag CLI 8.9초, 수집 실패 뒤 CLI 겹침 | 실행기만: 시작 전 최대 로그 id 하한·인덱스 조인(DB 약 24ms, 같은 1,352행), 부하 중 lag CLI 끔(계약 개정 5), lag 시도 시각 기록·실패 분류 코드, k6 교차 시계 진단 기록(개정 6). 앱·EC2 변경 없음 | 5 RPS [r36](runs/20261108T132548+0900-ec2-e2e-rps5-r36.md), 11 RPS r04~r06, 13 RPS r02~r04 | 5 RPS 호스트 CPU 58.0 → 47.1%. 11·13 RPS 각 3/3 PASS(합산 p95 852 / 2,040ms), 13 RPS 한계 신호 사라짐. 계약 개정 4 → 6 차이 기록. [요약본](<트러블슈팅_8(요약본).md>) · [상세본](<트러블슈팅_8(상세본).md>) · [개정 6 증거](evidence/20261108-rev6-11-13rps-formal.json) |
| AI 구간 대기열(단일 직렬 소비자, 트러블슈팅_8 2부) | 개정 6 13 RPS r02~r04(서버 p95 AI 합산 2,040.4ms, AI 구간 p95 1,880.8ms) | outbox 34~39ms·AI 결과 소비 lag 0·로그 수집 정상, AI 구간만 증가. AI는 스레드 1개가 1건씩 처리하고 파티션은 1개. AI CPU 메시지당 약 45~50ms. PyTorch 스레드는 이미 1개(경합 가설 기각) | 대안 A: `ai-request-topic` 파티션 2(backend `AiRequestTopicConfig`) + AI uvicorn 프로세스 2(`AI_UVICORN_WORKERS`, 기본 2) + `OMP_NUM_THREADS=1`. AI 코드 변경 없음. `1ec9c858` 2026/11/08 15:07 배포 | 13 RPS [r05](runs/20261108T151802+0900-ec2-step-rps13-r05.md)~[r07](runs/20261108T153018+0900-ec2-step-rps13-r07.md)(준비 회차 pilot r05 후) | **판정 미충족·가설 기각.** FAIL 1·PASS 2, AI 구간 p95 1,881 → 3,037ms(첫 회차 제외 1,782ms), 호스트 CPU 81 → 88~98%. AI CPU는 그대로이고, 서버 전체 CPU가 묶여 병렬화가 처리량을 만들지 못함. 배포 직후 backend 예열(CPU 49→24%) 영향 섞임. 메모리 3.89GB(충족). 사용자 결정으로 AI 프로세스 기본값 1로 되돌림(파티션 2 유지, `b56b5cab` 15:58 배포·확인, AI 메모리 610MiB). 실험 기간 메시지 4,868건이 두 파티션에 49:51로 나뉘어 병렬 소비 자체는 동작함. [되돌리기 확인](evidence/20261108-ai-workers-rollback-check.json) · [비교 증거](evidence/20261108-ai-workers-13rps-after.json) · [배포 확인](evidence/20261108-ai-workers-deploy-check.json) |

트러블슈팅_1~4를 거친 단계별 p99와 회차별 범위는 [단계별 p99 추이](runs/20261107-ec2-p99-trend-ts1-ts4.md)에 모았다. 36표본 지표의 p99는 참고값이다.

위 행의 문제명·대상·우선순위는 측정에서 확인한 증거에 따라 정한다. 특정 DB 개선이나 파이프라인 변경을 미리 성과로 확정하지 않는다.

로컬에서 개선한 코드가 EC2에 배포돼 있다면 그 상태로 EC2 첫 기준선을 측정한다. 로컬 결과를 EC2의 개선 전 값으로 대신 쓰지 않는다. 비교 기준선과 모델·정책·데이터·서버 자원 등이 다르면 차이를 기록하고 필요한 새 기준선을 정한다. EC2에서 추가 병목·결함이 관측되지 않았다면 해당 범위와 한계를 기록한다.

## 기록·재개 방법

1. 이 목차의 최근 기록과 [공통 가이드](../README.md)를 읽고 EC2 준비·측정 대상·실행 범위를 정한다.
2. 보고서는 `docs/testing/ec2/runs/<실험-ID>.md`, 공유 증거는 `docs/testing/ec2/evidence/`, 원본은 `build/test-runs/<실험-ID>/`를 사용한다. 새 실험 ID의 환경은 `ec2`로 구분한다. P0 준비·사용자 제공 증거와 성능·부하 실측을 구분한다.
3. 실행·분석 후 이 목차에 회차·판정·증거·관측 사실·원인 가설·다음 작업을 갱신한다. 개선·재측정이면 기준선과 변경 내용을 연결한다.
4. 실패·중단 기록도 보존한다. 로컬 자료를 이동하거나 복사해 EC2 실측 결과로 표시하지 않는다.
