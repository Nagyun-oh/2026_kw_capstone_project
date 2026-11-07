# v2 실행 가이드

최종 갱신: **2026/11/05**

[측정 기준](e2e-plan-v2.md) · [로컬 진행 상태](README.md)

## 구현 상태

| 항목 | 구현 | 실제 연결 확인 |
| --- | --- | --- |
| WAF 생성 requestId 응답·요청 시작 시각·실험 표식 | 완료 | 2026/11/03 r13 실제 응답·로그 연결 확인 |
| 실험 요청→requestId→DB·alertId 연결 | 완료 | r13 측정 요청·DB·AI 각 11건, 탐지 probe 1건 확인 |
| 백엔드 커밋·전송 계측 | 사용자 적용 완료 | 사용자 제공 logId 4666·4716 로그로 정상·탐지·통합 전송 확인 |
| 실제 브라우저 수신·알림 DOM·대표 테이블 관측 | 완료 | r13 직접 관리자 로그인·출처별 알림·대표 테이블 확인 |
| 지연·정합성·중단·보고서·3회 집계 | 완료 | 보완 후 r16~r18 1건/초·120초 실제 3회와 원본 표본 합산 단계 모두 PASS. [결과](runs/20261103-local-e2e-rps1-after-outbox-stage.md). 이후 3·5건/초 각 1회 [예비 확인](runs/20261103T204004+0900-local-e2e-prechecks-r21.md) PASS. 두 부하의 정식 3회 단계는 미실행 |
| 승인된 로컬 계정의 자동 폼 로그인·순차 예비 확인 | 완료 | localhost origin 제한·숨김 입력·메모리 전용. 검증 4개 및 실제 r21·r22 로그인 성공. [실행 방법](prechecks.md) |

기존 `run_experiment.py`와 원본 결과는 유지한다. v2는 **별도 `run_e2e.py` 명령**이다. 기존 실행기에 `--profile local-e2e-v2`를 넣지 않는다.

2026/11/05 [EC2 P3 환경 분리](../ec2/P3.md)를 추가했다. 기본 환경은 계속 `local`이므로 아래 로컬 명령은 그대로 사용한다. `--environment ec2`는 현재 dry-run만 지원하며 로컬 목표·수집 경로로 EC2 부하를 실행하지 않는다.

## 1. 실행 준비

프로젝트 루트의 Windows PowerShell에서 실행한다.

```powershell
python -m venv build/e2e-venv
.\build\e2e-venv\Scripts\python.exe -m pip install -r scripts/testing/requirements-e2e.txt
```

기본값은 설치된 Chrome을 사용한다. Edge는 실행 명령에 `--channel msedge`를 붙인다. Playwright Chromium을 쓰려면 먼저 다음을 실행하고 `--channel chromium`을 사용한다.

```powershell
.\build\e2e-venv\Scripts\python.exe -m playwright install chromium
```

로그인 쿠키·비밀번호·storage state 파일은 보존하지 않는다. 기본 실행기는 매 회차 열린 브라우저에서 관리자가 직접 로그인한다. 사용자가 로컬 계정 사용을 명시적으로 허용했다면 [예비 확인 보조 실행기](prechecks.md)의 실제 폼 로그인을 사용할 수 있다. 2026/11/03 프로젝트 전용 가상환경에 Playwright 1.64.1 설치를 완료했다. 다른 환경은 위 설치 명령으로 준비한다.

`.env`의 `PIPELINE_TRACE_ENABLED=true`를 확인한다. 의존 서비스가 실행 중인 상태에서 변경한 프론트·백엔드 이미지를 반영하고 WAF를 재생성한다.

```powershell
docker compose --env-file .env -f compose.yaml up -d --build --no-deps backend frontend
docker compose --env-file .env -f compose.yaml up -d --force-recreate --no-deps waf
docker compose --env-file .env -f compose.yaml exec -T waf nginx -t
```

2026/11/03 백엔드·프론트 이미지를 빌드하고 기존 AI 이미지·DB·볼륨을 유지해 로컬 서비스를 기동했다. 시작 시 반영된 WAF 설정의 `nginx -t`가 통과했고 실제 HTTP 200 응답에서 두 계측 헤더를 확인했다. Docker 소켓 권한이 필요하며 기동 오류가 있으면 측정하지 않는다.

실행 전 Windows 여유 메모리가 최소 1GiB 이상이어야 한다. r10은 941,449,216바이트로 이 준비 기준에 걸려 브라우저·부하 시작 전에 중단됐다. 사용하지 않는 앱은 사용자가 정리하고 새 ID로 재시도한다. 기준을 낮추거나 사용자 앱을 자동 종료하지 않는다. 브라우저 실행 여유를 위해 2GiB 이상 확보를 권장한다.

실험 요청은 IPv4 루프백으로 접속하고 HTTP `Host: localhost`를 유지한다. Python probe는 `127.0.0.1`로 직접 접속하며 k6는 `hosts`로 localhost를 같은 IPv4에 매핑한다. r12의 정상 확인 요청은 HTTP 200이지만 왕복 2048.190ms로 시계 확인을 통과하지 못했다. [별도 정상 요청 진단](evidence/20261103-local-transport.json)에서 localhost는 약 2초, 동일 Host의 IPv4는 6~22ms였다. 이는 발생기 연결 경로 보정이며 서버 파이프라인 개선 성과로 계산하지 않는다. 이전 실패 기록·100ms 기준은 보존한다.

## 2. 부하 없는 계획 확인

```powershell
.\build\e2e-venv\Scripts\python.exe scripts/testing/run_e2e.py --dry-run --rate 1
```

dry-run은 HTTP·Docker·브라우저를 호출하거나 회차 파일을 만들지 않는다.

## 3. 작은 실제 연결 검증

발생기 IP의 현재 차단·제외 정책을 확인한 뒤 실행한다. `--confirm-ip-policy`는 확인 사실의 기록이며 화이트리스트를 변경하는 명령이 아니다. 예상 밖 403이면 중단한다.

```powershell
.\build\e2e-venv\Scripts\python.exe scripts/testing/run_e2e.py --execute --connection-check --round 10 --confirm-ip-policy
```

열린 자동화 브라우저에서 **로컬 관리자 대시보드에 직접 로그인**한다. 실제 프론트의 인증·CSRF·STOMP 연결이 준비되지 않으면 부하를 시작하지 않는다. 기본 로그인 대기는 180초다.

연결 검증은 워밍업 10초·측정 10초·최종 관측 최대 60초를 사용한다. 정식 실험의 120초 기준선·3회 반복을 대신하지 않는다. 먼저 정상 요청 한 건으로 서버 ID·밀리초 시각 헤더와 발생기/VM 시계의 100ms 관측 범위를 확인한다. 이 요청도 warmup으로 별도 기록한다.

검증 fixture는 `scripts/testing/fixtures/juiceshop-login.json`이다. 사용자가 제공한 로컬 POST `/rest/user/login` SQL 삽입 재현 요청만 사용하고 쿠키·IP·실계정 정보는 포함하지 않는다. 본문·User-Agent가 실제 두 탐지를 발생시키는지 이 연결 검증에서 다시 확인한다. 미탐은 알림 손실로 단정하지 않는다.

## 4. 본 측정 1→3→5건/초

2026/11/03 r14 PASS·r15 INCONCLUSIVE 후 [AI 결과 처리 문제](20261103-rps1-baseline-review.md)를 보완했고, 새 r16·r17·r18의 1건/초 단계는 모두 PASS했다. 이후 사용자가 로컬 범위를 3·5건/초 각각 한 번의 예비 확인으로 좁혔고 r21·r22 모두 PASS했다. 다음은 EC2 준비다. 아래는 정식 단계 실행 방법의 예시이며 기존 회차 번호를 재사용하지 않는다. 서로 다른 코드·요청률의 회차를 하나의 3회 단계 집계로 섞지 않는다.

연결 검증 r13 PASS 후 초당 1건을 서로 다른 회차로 3번 실행한다. 아래는 연결 검증 r10~r13과 구분한 정식 회차 번호다.

```powershell
.\build\e2e-venv\Scripts\python.exe scripts/testing/run_e2e.py --execute --rate 1 --round 14 --confirm-ip-policy
.\build\e2e-venv\Scripts\python.exe scripts/testing/run_e2e.py --execute --rate 1 --round 15 --confirm-ip-policy
.\build\e2e-venv\Scripts\python.exe scripts/testing/run_e2e.py --execute --rate 1 --round 16 --confirm-ip-policy
```

각 회차 워밍업 30초·측정 120초다. 10초당 탐지 probe 1개는 총 요청률에 포함된다. 일반 부하는 k6, probe는 제어기가 보내며 두 요청원을 합쳐 초당 1·3·5건이다. probe는 동시 1개, k6는 최대 9 VU다. 알림을 관측한 뒤 해당 테스트 알림을 닫아 화면을 정리하며, 종료 후 대표 위협 한 건을 기존 위협 번호 검색으로 확인한다.

같은 부하 3회 모두 PASS인지 확인한 후 `--rate 3`, 이후 `--rate 5`로 진행한다. 현재 실행기는 회차 하나를 실행한다. 높은 단계를 자동 실행하지 않는다. 실패·미확인 회차를 지우지 않고 새 ID로 재실행한다.

## 5. 읽을 파일과 단계 집계

| 파일 | 확인할 내용 |
| --- | --- |
| `docs/testing/local/runs/<ID>.md` | STAR-T, 판정·이유, AI/WAF 서버·수신·DOM 지연 |
| `build/test-runs/<ID>/manifest.json` | 계약·fixture·소스 해시, 도구·이미지, 시계 확인, 시작 DB 건수 |
| `client-requests.jsonl` | phase·kind·순번→서버 requestId, UTC/제어기 시각 |
| `database.json`, `pipeline-events.jsonl` | 실제 DB 연결·최종 수와 UTC 커밋·전송 기록 |
| `browser-events.jsonl` | 실제 alertId·revision·출처 수신·DOM 확인 |
| `dashboard-api.jsonl` | 기존 화면 재조회 API의 endpoint별 진단 지연. 인증 요청 제외 |
| `progress.jsonl` | 부하 중·종료 후 lag·업무 완료 누적 수·표본 시각 |
| `metrics.json` | 구간별 평균·p50·p95·p99·최대·누락 수, 원본 지연 표본·정합성·해시 |

원본은 위 회차 디렉터리 아래에 있다. DB DATETIME은 지연 계산에 사용하지 않는다. `DG_TRACE.at`의 UTC와 WAF epoch를 사용한다. 브라우저 C0/C1/C2는 동일 Python `perf_counter`이며 IPC·DOM 관측 비용을 포함한다.

동일 조건의 3개 회차 디렉터리를 지정해 단계 보고서를 만든다. 아래 ID는 실제 생성된 ID로 바꾼다.

```powershell
python scripts/testing/summarize_e2e.py --runs "build/test-runs/실험-ID-1" "build/test-runs/실험-ID-2" "build/test-runs/실험-ID-3" --output "docs/testing/local/runs/local-e2e-rps1-stage.md"
```

기존 파일을 덮어쓰지 않는다. 부하·fixture·계약·코드·이미지·도구 조건이 다르면 합산을 거부한다. 원본 지연 표본을 모아 백분위를 다시 계산하며 p99의 평균을 사용하지 않는다. DB 규모·캐시·동시 트래픽은 별도로 비교해야 한다.

## 확인한 검증과 남은 한계

- Python 모의 테스트, 프론트 관측기·DOM 테스트, 프론트 production 빌드, WAF 메타데이터 계산·설정 정적 테스트를 실행했다.
- WAF 전체 shell 회귀 테스트는 Windows bash/인코딩 환경에서 실패했다. 이번 변경의 Nginx 실기동 검증을 대신하지 않는다.
- Playwright 설치·Nginx 기동/문법 검사·응답 헤더 확인은 2026/11/03 완료했다. 실제 브라우저 로그인·전체 E2E 성공 여부는 회차 보고서로 확인하며 모의 테스트를 실제 전달 성공으로 표시하지 않는다.
- WAF 시각은 `$msec - $request_time`으로 산출한 밀리초 단위 시작 관측값이다. 현재 서버가 외부 클라이언트 헤더를 신뢰하도록 바꾸지 않는다.
- 보고서의 DOM 가시성은 픽셀 렌더링 완료를 보장하지 않는다. 각 구간의 관측 오차와 작은 probe 표본 수를 함께 해석한다.
