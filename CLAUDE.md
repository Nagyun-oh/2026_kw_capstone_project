# CLAUDE.md

Claude Code용 작업 메모다. **공통 규칙은 [AGENTS.md](AGENTS.md)를 따르며 충돌 시 AGENTS.md가 우선한다.** AGENTS.md가 컨텍스트에 없으면 먼저 읽는다. 이 파일은 반복 탐색·확인을 줄이기 위한 실행 사실만 담는다. 상세 절차·결과는 링크한 문서에 두고 여기에 복제하지 않는다.

## 세션 시작

1. 실험·EC2 작업이면 [전달문](docs/testing/claude-handoff.md) → 해당 환경 목차([로컬](docs/testing/local/README.md) · [EC2](docs/testing/ec2/README.md))의 최근 기록·다음 작업 순서로 읽는다. 진행 상태의 기준은 환경 목차다.
2. 작업 트리는 미추적 파일이 많아 `git status --short` 출력이 길다. 먼저 이름·개수만 본다.

```bash
git branch --show-current
git diff --cached --name-status
git diff --stat | tail -n 1
git ls-files --others --exclude-standard | wc -l
```

3. 신규 파일이 staged(A)인데 작업 파일이 더 새로운 경우(AM)가 있다. 커밋을 요청받으면 파일을 명시해 다시 스테이징하고 `git add -A`는 쓰지 않는다.

## 현재 단계 (2026/11/05)

- 로컬 E2E 완료. 지금은 EC2 측정 준비 단계이며 진행표는 EC2 목차의 P0~P8이다.
- outbox·결과 재시도/DLT·계측 코드, `scripts/testing/`, `docs/testing/`은 아직 커밋되지 않았다. 로컬에 저장된 `origin/develop`·`origin/main`에도 없다.
- 배포 순서와 롤백은 [배포 절차서](docs/testing/ec2/deploy-runbook-outbox-trace.md)를 따른다.

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
| 실행기 모의 테스트 | `./build/e2e-venv/Scripts/python.exe -X utf8 -m unittest discover -s scripts/testing -p "test_*.py"` | 114개, 약 2초. 서비스 불필요 |
| WAF 계측 메타데이터 | `python -X utf8 -m unittest discover -s waf/tests -p test_measurement_metadata.py -v` | 2개, 서비스 불필요 |
| 미추적 문서 공백 | `grep -nE "[[:space:]]+$" <파일>` | `git diff --check`는 미추적 파일을 검사하지 않음 |

backend·frontend·WAF 전체 검증은 AGENTS.md의 표를 따른다.

## 탐색 지도

읽지 않을 곳: `build/test-runs/`(원본, 필요한 회차의 `metrics.json`·`manifest.json` 요약 필드만), `build/`의 기타 백업, `node_modules`, `frontend/build`, `AI_new/models`, `waf/logs`. 로컬 회차 보고서 `docs/testing/local/runs/`는 목차 표에서 필요한 회차만 연다.

| 영역 | 파일 |
| --- | --- |
| E2E 실행·수집 | `scripts/testing/run_e2e.py`(실행 순서 제어, 로컬 Compose 기반 수집) |
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
- 기존 실행기는 localhost·127.0.0.1, `compose.yaml`, `docs/testing/local/runs/` 경로를 가정한다. 주소 제한만 풀어 EC2에 쓰지 않는다.
- 기존 probe는 같은 요청에서 WAF·AI가 함께 탐지되는 입력이다. EC2에서는 발생기 IP 자동 차단 정책을 정하기 전에 보내지 않는다.

## 작업 방식

- 실험 실행·수집·보고는 자동화를 적극 구현한다. 병목 개선은 사용자가 원리를 이해하며 진행하므로 관측 근거, 원인 가설, 대안 비교를 먼저 설명하고 승인 후 작은 단위로 바꾼다.
- 진행 상황은 환경 목차에, 상세 해결 과정은 `docs/testing/ec2/보고서양식2(자세한 해결과정).md`, 포트폴리오용 핵심 요약은 `docs/testing/ec2/보고서양식1(핵심 요약).md` 양식으로 기록한다.
- 이 파일의 사실이 바뀌면 날짜와 함께 고친다. 길어지는 내용은 관련 문서로 옮기고 링크만 남긴다.
