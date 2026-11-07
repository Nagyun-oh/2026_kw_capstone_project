# CLAUDE.md

Claude Code용 작업 메모다. **공통 규칙은 [AGENTS.md](AGENTS.md)를 따르며 충돌 시 AGENTS.md가 우선한다.** AGENTS.md가 컨텍스트에 없으면 먼저 읽는다. 이 파일은 반복 탐색·확인을 줄이기 위한 실행 사실만 담는다. 상세 절차·결과는 링크한 문서에 두고 여기에 복제하지 않는다.

## 세션 시작

1. 실험·EC2 작업이면 [전달문](docs/testing/claude-handoff.md) → 해당 환경 목차([로컬](docs/testing/local/README.md) · [EC2](docs/testing/ec2/README.md))의 최근 기록·다음 작업 순서로 읽는다. 진행 상태의 기준은 환경 목차다.
2. 작업 트리 상태는 매번 확인한다. 출력이 길면 먼저 이름·개수만 본다.

```bash
git branch --show-current
git diff --cached --name-status
git diff --stat | tail -n 1
git ls-files --others --exclude-standard | wc -l
```

3. staged 내용과 작업 파일이 다르면(AM) 커밋을 요청받았을 때 파일을 명시해 다시 스테이징한다. 기존 사용자 변경을 포함하는 `git add -A`는 쓰지 않는다.

## 현재 단계 (2026/11/06)

- 로컬 E2E 완료. EC2 P0~P8 및 정식 1·3·5 RPS·120초·각 3회 모두 PASS. 다음은 구간별 지연·완료 EPS·lag·자원 분석이며 진행표는 EC2 목차다. 최대 처리량·knee point는 미확정이다.
- outbox·결과 재시도/DLT·계측 코드와 기존 실험 도구·문서는 `d6ec7c4b`에 커밋됐다. EC2 HEAD는 `e50029b1`이며 앱 이미지 3개 태그와 일치하고 d6ec7c4b를 포함한다. 5 RPS 정식 세 회차 종료 후에도 같은 SHA·9서비스 정상·원복을 확인했다. 원격 수집·전체 실행기는 이번 작업 트리에 추가됐다.
- 배포 순서와 롤백은 [AWS 배포 문서](docs/06_aws_deployment.md)와 [CI/CD 문서](docs/07_cicd_pipeline.md)를 따른다. 삭제된 별도 배포 절차서는 참조하지 않는다.
- EC2 P0는 실제 SSH 조회와 사용자 콘솔 자료로 완료했다. [r03 보고서](docs/testing/ec2/runs/20261105T165534+0900-ec2-inventory-r03.md)에 버전·DB·lag·자원과 크레딧 unlimited/864(16:50 KST)를 기록했다. [수집 가이드](docs/testing/ec2/P0.md)를 따르고 부하 직전·종료 후 크레딧을 새 시각으로 확인한다.
- P1·P3~P7 완료. [P7](docs/testing/ec2/P7.md)은 실제 로그인·정상 3건·probe 1건의 저장/AI 완료·두 출처 알림 수신/DOM·임시 제외 보고·원복까지 확인했다. 복구 요청 포함 최종 5건 완료·lag 0·9서비스 실행. 남았던 대표 행도 [20:54 실환경 재확인 PASS](docs/testing/ec2/runs/20261105T205423+0900-ec2-table-recheck-r01.md)로 종결했다. 기존 위협 681·로그 8265·WAF 681·AI 682의 단일 행과 상세 버튼 확인이며 새 probe·차단 변경 없음. r03 원본 INCONCLUSIVE는 보존. [완료 증거](docs/testing/ec2/evidence/20261105-p7-completion.json). 실제 IP는 공유하지 않는다.
- P7에서 Windows Python 3.12의 거친 UTC 시각 조회를 발견해 정밀 Windows UTC API로 보완했다. 허용 오차·시계 점프 검사는 완화하지 않았다. 이전 실패 회차 원본·판정은 보존했다.
- P8 완료. [기준·실행 가이드](docs/testing/ec2/P8.md): AI/WAF 서버 p95 각각 3초, 60초 내 정리·정합성·두 출처 DOM, 정식 1→3→5 RPS·120초·3회. 전용 `run_ec2_e2e.py`가 원격 초기화·감시·DB 전후·자동 로그인·원복을 연결한다. 숨김 입력으로 메모리에만 보관하며 임시 제어기는 성공 후 종료했다. 기존 `run_e2e.py`의 EC2 실행 경로는 계속 차단한다.
- P8 pilot [r03](docs/testing/ec2/runs/20261105T215318+0900-ec2-pilot-r03.md) PASS: 측정 60건·DB 60·AI 완료 60·probe 6 두 출처 수신/DOM, 서버 p95 AI 약 997ms/WAF 약 569ms, DB 전후 비교·대표 행·원복 확인. 복구 요청 포함 최종 92건 완료·lag 0·9서비스 정상. [완료 증거](docs/testing/ec2/evidence/20261105-p8-completion.json). pilot은 정식 반복 통계에 합산하지 않는다.
- 정식 1 RPS·120초·3회(r01 22:17, r02 22:22, r03 22:28 KST) 모두 PASS. 총 360건 저장·AI 완료·probe 36건. 합산 서버 p95 AI 1,004ms/WAF 608ms. 원래 제외·발생기 블랙리스트 상태 복구, 전체 456건 저장·AI 완료·lag 0·9서비스 정상 확인. [기준선](docs/testing/ec2/runs/20261105-ec2-1rps-baseline-review.md). 앱/실행기 로직 변경 없음. 최신 CPU 크레딧은 미수집, p99는 참고값.
- 정식 3 RPS·120초·3회(r02 22:50, r03 22:56, r04 23:02 KST) 모두 PASS. 총 1,080건 저장·AI 완료·probe 36건, 합산 서버 p95 AI 1,017ms/WAF 614ms. 원복 후 전체 1,176건 저장·AI 완료·lag 0·9서비스 정상. [3 RPS 기준선](docs/testing/ec2/runs/20261105-ec2-3rps-baseline-review.md) · [1↔3 비교](docs/testing/ec2/runs/20261105-ec2-1rps-vs-3rps.md). 사전 DB root 인증 실패 r01은 부하 0건·WAF 변경 없이 INCONCLUSIVE로 보존했고 새 ID로 측정했다. 이 단계 원본·판정은 보존한다. 10 RPS 이상은 별도 상한·안전 조건 확인 후 진행한다.
- 2026/11/06 정식 5 RPS·120초·3회 r05~r07 모두 PASS. 측정 1,800건 저장·AI 완료·probe 36건, 합산 서버 p95 AI 1,049ms/WAF 541ms. 원복 후 전체 1,896건 완료·lag 0·9서비스 정상. [5 RPS](docs/testing/ec2/runs/20261106-ec2-5rps-baseline-review.md) · [1·3·5 비교](docs/testing/ec2/runs/20261106-ec2-1-3-5rps-comparison.md). 숨김 입력 제어기는 종료하며 앱·배포·DB 구조·SLO는 변경하지 않았다.
- 5 RPS 계측 중단 r01과 r04는 INCONCLUSIVE, 첫 보완 버전 r02/r03은 개별 PASS로 보존하고 새 정식 세 회차에 섞지 않았다. 시계 경과 검증은 표시용 datetime 대신 같은 SSH 교환의 정밀 UTC·단조 시계 쌍을 사용한다. Nginx/k6의 실제 1ms 해상도를 전파하고, 모순 시 실제 시계 재확인·기존 300초 기한·점프 중단·HTTP 미재전송을 유지한다. 1·3 RPS와 계측 해시 및 Chrome 156.0.8078.80 → 156.0.8078.81 차이를 비교 제한으로 기록했다. 전체 262개 회귀 및 중단 원본 HTTP 875표본 오프라인 재검증 통과. 최신 CPU 크레딧은 미수집이며 p99는 참고값이다.
- r01의 교차 시계 폭 20ms 전체 중단은 서버/PC 독립 시계 계산과 맞지 않아 개정 2에서 진단 전용으로 분리했다. 점프·모순·유효 기간 검사는 유지하며 3초 SLO는 그대로다. r02의 61건은 k6 종료 경계의 추가 예약으로, 송신 상한을 고친 r03은 정확히 60건이다. 두 INCONCLUSIVE 원본을 보존하고 서버 개선 효과로 주장하지 않는다.
- 2026/11/07 개선 비교. [트러블슈팅_1](<docs/testing/ec2/트러블슈팅_1(상세본).md>): 알림 발행 250ms 비교(r10·r12·r13) 후 EC2 운영 적용, 호스트 오버라이드 `compose.alerts.override.yaml` 사용. [트러블슈팅_2](<docs/testing/ec2/트러블슈팅_2(상세본).md>): AI outbox 250ms r14~r16 3/3 PASS, outbox 평균 300.9→163.7ms. 15:05 EC2 운영 적용, 같은 호스트 오버라이드에 두 키 공존. 저장소 `compose.aws.yaml` 기본값 두 키 250ms(2026/11/07 커밋·미배포). 보조 제어기는 Git 제외 `build/testing-validation/ec2-ai-outbox-250ms-20261107/`. [트러블슈팅_3](<docs/testing/ec2/트러블슈팅_3(상세본).md>): 대시보드 로그 목록 전체 스캔 → `network_logs(created_at)` 인덱스 16:26 EC2 적용(앱 배포 불필요, 저장소 변경은 2026/11/07 커밋). r17~r19 3/3 PASS, 부하 중 로그 목록 127.7 → 0.7ms·호출당 검사 16,996 → 5.5행. AI 경로 p95 감소는 인덱스 효과로 주장하지 않는다. [트러블슈팅_4](<docs/testing/ec2/트러블슈팅_4(상세본).md>): Fluent Bit Flush 0.5→0.1 EC2 17:36 적용(호스트 사본 `~/.config/dualguard/fluent-bit.conf`를 같은 운영 오버라이드에 연결), r21~r23 3/3 PASS(r20 INCONCLUSIVE 보존). 로그 커밋 p95 521.8→165.3ms, AI 알림 표시 p95 1,133ms로 1초 목표 미달. 저장소 `waf/fluent-bit.conf` 0.1(2026/11/07 커밋·미배포). [트러블슈팅_5](<docs/testing/ec2/트러블슈팅_5(상세본).md>): 커밋 직후 발행기 깨우기(`AfterCommitDispatchTrigger`·`AiRequestOutboxWakeup`·`RequestAlertWakeup`, 각 발행기 단일 스레드 스케줄러 사용, 주기 조회는 복구용) 코드·테스트 완료(168개 통과·7개 건너뜀). 2026/11/07 커밋·미배포, 재측정 대기. 끄기 플래그는 `compose.aws.yaml`이 backend에 전달한다.

## 사용자 승인 없이 하지 않는 것

EC2 SSH·SSM 접속, 운영 URL 요청(단건 포함), Actions 실행·배포, DB DDL·DML, `.env*` 값 출력·수정, WAF 재생성·차단 제외 변경, 로컬 Compose 재기동·부하 실행, 커밋·push. 요청이 확인·설명·계획이면 문서 외 파일을 바꾸지 않는다.

## 환경·도구 (2026/11/05 확인)

| 항목 | 사실 |
| --- | --- |
| 셸 | Bash 도구는 Git Bash, PowerShell 5.1은 별도 도구. AGENTS.md 명령표는 PowerShell 기준 |
| Python | 시스템 3.12. 실행기 전용 가상환경 `build/e2e-venv`(Playwright 설치). 한국어 출력은 `-X utf8` |
| 기타 | k6·Node(nvm4w)·Docker Desktop 설치. `gh` 미설치라 Actions·PR 이력은 사용자에게 확인 |
| 원격 참조 | 마지막 fetch 시점의 값이다. 배포 상태 판단에 그대로 쓰지 않는다 |

## 확인된 빠른 검증

| 대상 | 명령 (루트, Bash) | 결과 |
| --- | --- | --- |
| 실행기 회귀 | `./build/e2e-venv/Scripts/python.exe -X utf8 -m unittest discover -s scripts/testing -p "test_*.py"` | 262개 통과(2026/11/06, 시계 회귀 10개 포함). 앱 서비스 불필요. Chrome 정적 DOM 재현·k6 순수 모듈 테스트 포함 |
| WAF 계측 메타데이터 | `python -X utf8 -m unittest discover -s waf/tests -p test_measurement_metadata.py -v` | 2개, 서비스 불필요 |
| 미추적 문서 공백 | `grep -nE "[[:space:]]+$" <파일>` | `git diff --check`는 미추적 파일을 검사하지 않음 |

backend·frontend·WAF 전체 검증은 AGENTS.md의 표를 따른다.

## 탐색 지도

읽지 않을 곳: `build/test-runs/`(원본, 필요한 회차의 `metrics.json`·`manifest.json` 요약 필드만), `build/`의 기타 백업, `node_modules`, `frontend/build`, `AI_new/models`, `waf/logs`. 로컬 회차 보고서 `docs/testing/local/runs/`는 목차 표에서 필요한 회차만 연다.

| 영역 | 파일 |
| --- | --- |
| E2E 실행·수집 | `scripts/testing/run_e2e.py`(로컬 실행·EC2 dry-run), `e2e_environment.py`(환경·허용 주소·경로) |
| EC2 원격 수집·실행 | `e2e_remote.py`·`ec2_collection_worker.py`, 수집 전용 `run_ec2_collection.py`와 전체 실행 `run_ec2_e2e.py`. P8 고정 계약 검증 |
| EC2 시계·중단 감시 | `ec2_watch.py`·`ec2_watch_worker.py`, 관측 전용 `run_ec2_watch.py`, `profiles/ec2-observation-v1.json`에 P8 계약 결합 |
| EC2 DB 전후 관측 | `ec2_db.py`·`ec2_db_worker.py`·`ec2_db_queries.py`, `run_ec2_db.py`. 컨테이너 root 인증은 1045이며 필요한 통계는 사용자 숨김 입력으로 실제 조회. 비밀번호 저장 없음 |
| 순수 파싱·판정 | `e2e_core.py`(요청·trace·DB·브라우저 연결, 판정), `pipeline.py`(분포·lag), `metrics.py` |
| 중단·기준 | `guard.py`, `load_policy.py`, `profiles/local-load-v1.json`, 계약 `docs/testing/local/e2e-plan-v2.json` |
| 집계·보조 | `summarize_e2e.py`(3회 합산), `run_local_prechecks.py`·`local_browser_login.py`(localhost 전용 로그인), `kafka_replay.py`(DLT 재처리), `run_experiment.py`(v1, 공통 `reserve`·`command`·`save`) |
| 브라우저 계측 | `scripts/testing/browser_trace.js`, `frontend/src/utils/e2eTrace.js`, `frontend/src/hooks/useWebSocket.js` |
| outbox·오류 처리 | `AiRequestOutboxService`·`Publisher`·`Dispatcher`·`Repository`, `PipelineKafkaErrorConfig`, `KafkaConsumerConfig`, `OutboxSchedulingConfig` |
| 계측 | `PipelineTrace`(`DG_TRACE`), `waf/njs/headers.js`, `waf/nginx-logging.conf.template` |

## 다시 조사하지 않아도 되는 사실

- outbox 저장소는 JdbcTemplate이라 `ddl-auto: validate`가 테이블 누락을 잡지 못한다. `LogService`는 `AI_OUTBOX_ENABLED`와 무관하게 항상 enqueue한다.
- WAF 템플릿·njs는 bind mount이며 컨테이너 시작 시 렌더링된다. `deploy.sh`는 WAF를 재생성하지 않는다.
- 로그·AI 결과 Consumer는 `kafkaListenerContainerFactory`(재시도·DLT), WAF Consumer는 `wafKafkaListenerContainerFactory`를 쓴다. group ID는 변경 전과 같다.
- 서버 구간 지연은 같은 호스트 시계(WAF 시작 epoch, `DG_TRACE`)로, 브라우저 구간은 발생기 `perf_counter`로 계산한다. 두 시계 비교는 연결 확인용이다.
- 실행기는 local/ec2 환경을 분리했다. 기존 `run_e2e.py`의 EC2 실행은 계속 차단하며 실제 EC2 부하는 `run_ec2_e2e.py`의 P8 고정 계약 경로를 사용한다. 주소 제한만 풀어 로컬 경로를 EC2에 쓰지 않는다.
- 기존 probe는 같은 요청에서 WAF·AI가 함께 탐지되는 입력이다. EC2 성능 실험에서는 발생기 IP 하나만 임시 제외하며 회차별 원복·시험 등록 정리를 확인한다. 이외 차단 정책은 유지한다.

## 작업 방식

- 실험 실행·수집·보고는 자동화를 적극 구현한다. 병목 개선은 사용자가 원리를 이해하며 진행하므로 관측 근거, 원인 가설, 대안 비교를 먼저 설명하고 승인 후 작은 단위로 바꾼다.
- 진행 상황은 환경 목차에, 상세 해결 과정은 `docs/testing/ec2/보고서양식2(자세한 해결과정).md`, 포트폴리오용 핵심 요약은 `docs/testing/ec2/보고서양식1(핵심 요약).md` 양식으로 기록한다.
- 이 파일의 사실이 바뀌면 날짜와 함께 고친다. 길어지는 내용은 관련 문서로 옮기고 링크만 남긴다.
