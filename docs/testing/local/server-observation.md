# 로컬 서버 계측 준비·검증

최종 갱신: **2026/11/01**

[로컬 진행 목차](README.md) · [공통 가이드](../README.md)

## 현재 구현·검증 범위

`scripts/testing/run_experiment.py`에 선택 옵션 `--observe-pipeline`을 추가했다. 기존 옵션 없는 실행은 `arrival-smoke-v3`의 스모크 검증을 유지한다. 새 옵션은 HTTP 판정에 `local-pipeline-v2` 관측 판정을 함께 반영한다. v2부터 DB 시각 해석 기준을 필수로 명시하고 원본 DATETIME도 보존한다.

**모의 테스트 47개와 r09의 실제 계측 검증을 통과했다.** 첫 r08은 수집기가 DB DATETIME을 UTC로 해석한 것이 실제 시각과 모순돼 INCONCLUSIVE였고, 원본·판정을 유지한 채 수집기를 보완해 새 r09를 실행했다. 백엔드·프론트·AI·Compose·DB 스키마·기존 DB 값은 변경하지 않았다.

| 회차 | 결과·근거 | 해석 |
| --- | --- | --- |
| [r08](runs/20261101T131829+0900-local-normal-smoke-r08.md) | HTTP 11건 모두 200, DB·고유 requestId·AI 완료 각 11. 시각 해석 모순으로 INCONCLUSIVE | UTC를 붙인 DB 시각이 AI 완료보다 약 9시간 뒤였음. DB 관련 지연 수치를 실제 성능으로 사용하지 않음 |
| [r09](runs/20261101T132341+0900-local-normal-smoke-r09.md) | HTTP 10건 모두 200, 평균 5.51ms·p95 8.95ms·p99 10.01ms·최대 10.27ms. DB·고유 requestId·AI 완료 각 10, PASS | 현재 로컬 저장 시각을 `+09:00`으로 명시해 UTC 변환. 수집 원본 14개 해시 일치, 실행기 파일 6개 해시 기록 |

r09에서 AI 요청 경로의 관측 최대 lag는 1, 다른 필수 경로는 0이었고 종료 후 연속 두 번 모두 0을 확인했다. DB 행 생성→AI 완료 로그 지연의 평균·p95·p99·최대는 40.54 / 57.71 / 69.14 / 72.00ms였다. WAF access→AI 완료 로그 p95는 635.35ms지만 시작 시각이 초 단위이므로 정밀한 요청 시작 지연으로 설명하지 않는다. 이 짧은 회차는 기준 부하·장애 안전성 검증 완료를 의미하지 않는다.

| 관측 | 구현한 내용 | 남은 한계 |
| --- | --- | --- |
| DB 저장 | 실험 URL이 정확히 같은 `network_logs`의 로그 ID·requestId·행 생성 시각·상태와 WAF·AI 탐지 건수 조회 | 읽기 전용 최종 상태 대조이며 DB 커밋 시각을 직접 계측하지 않음 |
| AI 처리 완료 | `AiResultConsumer`가 서비스 반환 후 출력하는 `AI analysis result received. logId=`를 로그 ID로 연결 | 서비스 성공 반환 관측. 추론 내부 시간·예외별 처리 결과·오래된 로그 유실은 별도 관측 필요 |
| 탐지 없는 완료 | 완료 로그가 있고 AI 탐지 행이 없는 로그를 `ai_handled_without_detection`으로 별도 집계 | 정상 판정의 원본 점수·모델 결과를 직접 수집하는 것은 아님 |
| Kafka lag | 4개 group·topic의 partition별 부하 전·중·종료 후 표본, 관측 최대값, 미확인 값 구분 | 간격 사이의 최고 lag·정확한 적체 해소 시각은 알 수 없음 |
| 비동기 지연 | WAF access→DB 행 생성, DB 행 생성→AI 완료 로그, WAF access→AI 완료 로그의 평균·p95·p99·최대·표본 수 | WAF 시각은 초 단위. 요청 시작→커밋 지연이나 정밀한 추론 지연으로 표현하지 않음 |
| 장애 최종 처리 | 완료 확인·미확인, 저장 부족·요청 ID 중복·AI 탐지 중복 구분 | 실패·정책상 제외·DLT의 요청별 집계와 알림 정합성은 미구현. 0 대신 `null`로 유지 |

소스의 `UtcDateTime` 규칙만으로 물리 DB DATETIME에 UTC를 붙이지 않는다. [읽기 전용 진단](evidence/20261101-local-db-time-basis.json)에서 DB 시계는 UTC, 실행 중 JDBC `serverTimezone`은 `Asia/Seoul`, r08의 저장값은 `+09:00`으로 해석해야 WAF·AI 관측 순서와 맞음을 확인했다. JDBC 바인딩·전체 과거 데이터의 저장 의미까지 검증한 것은 아니며, 앱 시간 처리의 전반적인 점검은 별도 과제다.

현재 로컬 r09는 이 근거로 `--db-time-offset +09:00`을 사용했다. 다른 환경·기간·코드의 데이터에 일반화하지 않는다. `+00:00` 또는 `+09:00`의 확인된 저장 기준을 실행 인자로 지정하면 SQL `CONVERT_TZ`로 UTC를 계산한다. 임의로 9시간을 더하거나 DB 값을 고치지 않으며 원본 DATETIME·선택 기준·변환 시각을 함께 기록한다. 시각 모순·누락은 관련 지연을 미측정으로 둔다. 시계 동기화도 별도 확인이 필요하다.

## 실제 계측 검증 전 확인

1. 프로젝트 루트에서 실행 중인 서비스 상태를 확인한다.

   ```powershell
   docker compose --env-file .env -f compose.yaml ps
   ```

2. WAF·Fluent Bit·Kafka·백엔드·AI·DB·JuiceShop이 준비돼 있어야 한다. 테스트 IP의 등록·제외 상태와 다른 사용자 트래픽도 확인한다.
3. 필수 Kafka 경로는 `log-group/log-topic`, `ai-service-group/ai-request-topic`, `ai-result-group/ai-result-topic`, `waf-detection-group/waf-detection-topic`이다. group·partition 누락이나 미확인 lag를 0으로 취급하지 않는다.
4. DB 조회는 `db` 컨테이너의 기존 `MYSQL_ROOT_PASSWORD`를 내부에서 사용한다. 비밀번호를 호스트 명령·보고서로 출력하지 않는다. 매 조회는 `START TRANSACTION READ ONLY`→실험 URL SELECT→`ROLLBACK`만 수행하며 테이블·계정·데이터를 변경하지 않는다. 접속 실패는 설정을 임의 변경하지 않고 사전 확인 실패로 기록한다.
5. 새 파이프라인 옵션은 사전 DB 조회·필수 Kafka 경로 확인에 실패하면 부하를 시작하지 않는다. r09에서 현재 로컬의 인증·SQL·완료 로그 연결을 확인했다. 환경이 바뀌면 시각 해석과 수집 경로를 다시 확인한다. 앱 재빌드는 필요하지 않다.

## 계측 검증 실행 방법: 1회/초 × 10초

아래는 실제 r09 실행 조건이다. 재실행 시에는 새 회차 번호를 사용한다. 현재 계측 확인은 끝났으므로 다음 본 실험의 기준을 정하기 전에 불필요하게 반복하지 않는다.

```powershell
python .\scripts\testing\run_experiment.py --dry-run --observe-pipeline --db-time-offset +09:00 --url http://localhost/ --rate 1 --seconds 10 --round 9
python .\scripts\testing\run_experiment.py --execute --observe-pipeline --db-time-offset +09:00 --url http://localhost/ --rate 1 --seconds 10 --round 9
```

첫 명령은 계획만 출력한다. 두 번째 명령만 HTTP 요청·읽기 전용 수집·보고서 파일 생성을 수행한다. 실제 요청 건수는 계획 10건과 차이가 있을 수 있으므로 실측 HTTP 건수와 최종 DB·AI 완료 수를 대조한다.

| 실행 전 확정한 기준 | 값·의미 |
| --- | --- |
| 요청·부하 상한 | 로컬 HTTP 80, 1회/초 × 10초, 기존 10 VU 상한·요청 제한 10초 유지 |
| HTTP 수집 | 요청·완료 반복이 양수·동일, 모두 200, dropped_iterations 0, 평균·p95·p99·최대값 확보 |
| 저장·AI 완료 | 실제 HTTP 요청 수 = 저장 로그 수 = 고유 requestId 수 = AI 처리 완료 로그가 확인된 로그 수, 요청 ID 누락·중복 및 동일 로그의 중복 AI 탐지 행 없음 |
| lag·최종 대기 | 기본 lag 간격 10초 + 명령 소요 시간, 부하 후 최대 30초 + 진행 중인 최종 수집 명령 소요 시간. DB·AI 완료 조건과 함께 연속 두 번 필수 partition lag 0 확인 |
| 관측 충분성 | 부하 중 lag 표본, 필요한 시각·DB·완료 로그를 확보. 수집 오류·시각 누락 등은 INCONCLUSIVE 근거로 보존 |
| 성능 목표 | 계측 검증이 목적. HTTP·비동기 p95·p99 성능 보장 상한은 아직 미정 |
| 중단·복구 | 예상 밖 403·오류·서비스 이상을 보면 부하를 확대하지 않는다. 필요 시 Ctrl+C로 k6 종료·수집 스레드 종료 후 기록 보존. 서비스·DB를 초기화하거나 재시작하는 자동 복구는 없음 |

`--lag-interval`은 5~30초, `--drain-seconds`는 1~120초로 설정할 수 있다. Kafka CLI와 DB·로그 조회 소요 시간은 간격에 추가된다. 최종 대기에는 진행 중인 명령이 최대 각 15초까지 더 걸릴 수 있으며, 짧은 대기 시간을 잡으면 두 번 확인하기 전에 INCONCLUSIVE로 끝날 수 있다.

## 결과 확인

보고서는 기존 `docs/testing/local/runs/<실험-ID>.md`, 원본은 `build/test-runs/<실험-ID>/`에 저장한다.

| 파일·필드 | 확인할 내용 |
| --- | --- |
| `manifest.json` | `observe_pipeline`, `observation_version`, DB 시각 해석 기준, 간격·대기 시간, 앱 이미지·실행기 파일 해시·부하 조건 |
| `metrics.json`의 `http` | HTTP 평균·p95·p99·최대·실제 건수·반복 완료 |
| `metrics.json`의 `pipeline.counts` | HTTP·DB·고유 requestId·AI 완료·탐지 유무·미확인·중복 구분 |
| `metrics.json`의 `pipeline.latency_ms` | 각 관측 구간의 지연과 유효 표본 수. 시간 해상도·누락 건수 함께 확인 |
| `raw/kafka-during-*.json`, `raw/kafka-drain-*.json` | 실제 수집 시각·명령 시간·partition lag. 관측 최대값은 `pipeline.lag_maxima` |
| `raw/pipeline-db-*.json`, `raw/pipeline-ai-*.json` | 원본 대조에 필요한 ID·시각·건수만 저장. IP·본문·원문 애플리케이션 로그는 저장하지 않음 |
| `raw/pipeline-summary.json` | 추가 관측 판정·근거·시간 해석·미측정 항목 |

전체 판정은 HTTP와 추가 관측 중 FAIL이 있으면 FAIL, FAIL 없이 증거 부족이면 INCONCLUSIVE다. 정상 수집된 최종 DB 로그 수가 대기 구간 내 HTTP 건수와 다르면 해당 도착 기준 FAIL이며, 영구 데이터 유실을 확정한 것은 아니다. lag 0이어도 AI 완료 로그가 없으면 처리를 완료했다고 간주하지 않는다.

로컬 목차에 r08·r09·시각 진단을 연결했다. 새 계측은 수집 부하가 추가되므로 r07과 단순 응답 시간 차이를 개선 효과로 계산하지 않는다. 이후 [기존 JSON 기준](../../../scripts/testing/profiles/local-load-v1.json)을 확정하고 `local-load-v1` 판정·자동 감시를 구현했다. 장애 실험 전에는 미구현한 실패·정책상 제외·DLT·알림 관측을 시나리오에 맞춰 추가한다.

이후 사용자가 AI·WAF 두 경로를 대시보드까지 나누어 측정하도록 범위를 구체화해 [local-e2e-v2](e2e-plan-v2.md) 명세를 추가했다. 위 기록은 서버 범위의 준비·검증 이력이며 현재 다음 작업은 v2의 정밀 시각·브라우저 계측 구현이다. 기존 collector 이름 `local-pipeline-v2`를 전체 E2E 구현 완료로 해석하지 않는다.

현재 서버 실행기의 비동기 구간별 결과에는 참고 지표 `p50_ms`를 추가했다. HTTP도 k6 중앙값을 `http_p50_ms`로 결과·보고서에 연결한다. 기존 목표·판정·시각 해석은 유지하며 r08·r09 원본과 보고서를 다시 생성하지 않는다.

이후 v2 WAF·브라우저 관측과 별도 실행기 구현·모의 검증을 완료했다. 현재 다음 작업은 [실행 가이드](e2e-runner.md)에 따른 실제 반영·로그인·소량 연결 검증이다. 이번 구현에서 DB 시간대·기존 원본을 변경하지 않았다.
