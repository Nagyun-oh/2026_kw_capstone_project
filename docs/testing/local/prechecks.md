# 로컬 3·5RPS 예비 확인

최종 갱신: **2026/11/03**

[로컬 목차](README.md) · [E2E 실행 가이드](e2e-runner.md)

## 이번 범위

1RPS 3회 재측정 후, 사용자가 **로컬 3RPS·5RPS를 각각 1회 확인하고 EC2로 이동**하기로 정했다. 두 부하 모두 워밍업 30초 제외·측정 120초이며 기존 v2 회차별 지연·정합성·중단 기준을 유지한다.

3RPS가 PASS일 때만 5RPS를 실행한다. 실패·미확인이면 부하 상승을 중단한다. 각 1회 결과는 예비 확인이며, 부하별 3회 반복 단계 통과나 최대 처리량으로 표현하지 않는다. 서로 다른 요청률의 지연 표본을 합산하지 않는다.

## 자동 로그인

사용자가 로컬 계정 사용을 명시적으로 허용한 경우 아래 보조 실행기를 사용할 수 있다.

```powershell
cd C:\Projects\2026_kw_capstone_project
.\build\e2e-venv\Scripts\python.exe scripts/testing/run_local_prechecks.py --execute --start-round 21 --confirm-ip-policy
```

시작 회차 번호는 기존에 사용하지 않은 번호로 바꾼다. 숨김 콘솔 입력으로 계정·비밀번호를 받아 메모리에 보관하고, 각 회차의 새 브라우저에서 실제 로그인 폼을 제출한다. 자격 증명을 CLI 인자·환경 파일·보고서·세션 파일로 저장하지 않는다.

- 자동 입력 대상은 `http://localhost:3000` 또는 `http://127.0.0.1:3000`뿐이다.
- 실제 관리자 세션·CSRF·STOMP 구독 준비를 거친다. 인증 우회·가짜 알림 주입은 하지 않는다.
- 로그인 폼 처리 중 예외는 원문 인자를 기록하지 않도록 가린다.
- 측정·정합성 판정은 기존 `run_e2e.py`를 그대로 호출한다. 차이는 인증 입력과 순차 실행·보고서의 예비 확인 표기다.
- 앱·DB·토픽·offset·차단 정책을 변경하지 않는다. 사용자 앱을 자동 종료하거나 메모리 제한을 바꿔 기준을 통과시키지 않는다.

수동 로그인이 필요하면 기존 `run_e2e.py`를 계속 사용한다. 계정 정보를 모르는 환경에서 임의로 찾아 쓰지 않는다.

## 준비와 중단

Docker 엔진과 필수 서비스가 준비돼 있어야 한다. 재기동 직후의 모델·JVM 로딩·호스트 메모리 상태도 확인한다. 기존 호스트 여유 메모리 중단 기준은 **1GiB 미만 15초 지속**, 브라우저 실행 전 2GiB 이상 확보는 권장 사항이다.

첫 시도 r19는 자동 로그인 성공 후 1RPS 워밍업 중 메모리 기준에 걸려 INCONCLUSIVE였다. 실제 3RPS 측정·5RPS 실행은 없었다. 테스트 브라우저 종료 후 기존 요청 24건의 저장·AI 완료·outbox SENT를 읽기 전용으로 대조했다. [중단 근거](evidence/20261103-local-prechecks-memory-stop.json)

기동 직후 압박이 완화된 뒤 새 ID의 r21로 재시도했다. 3RPS r21·5RPS r22 각 1회 모두 PASS했고, 측정 요청·DB·AI 완료·outbox SENT는 각각 361건·600건으로 일치했다. 각 probe 12건의 두 출처 수신·DOM도 확인했다. [결과 보고서](runs/20261103T204004+0900-local-e2e-prechecks-r21.md)와 [사후 대조](evidence/20261103-local-prechecks-verification.json)를 참고한다. 원래 r19와 중단 원본은 보존한다. 로컬 추가 부하는 마무리하고 다음은 EC2 측정 준비다.

## 검증 코드

- `scripts/testing/local_browser_login.py`: 로컬 origin 제한·실제 폼 입력·실제 구독 준비 확인·예외 가림.
- `scripts/testing/test_local_browser_login.py`: origin 거부, 정상 폼 입력, 인증 실패, 예외의 비밀값 가림을 확인하는 대역 테스트 4개.
- `scripts/testing/run_local_prechecks.py`: 비밀값 없는 사전 계획 생성·3→5 순차 실행·첫 회차 실패 시 상승 중단.

개별 회차의 원본은 기존 `build/test-runs/<ID>/`, 보고서는 `docs/testing/local/runs/<ID>.md`다. 묶음 계획도 별도 ID로 남기며 인증 이벤트에는 계정값을 포함하지 않는다.
