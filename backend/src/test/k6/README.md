# k6 Backend Load Test

## 개요

이 디렉토리는 Spring Boot 백엔드 API의 기본 응답 상태와 부하 상황에서의 성능을 확인하기 위한 k6 테스트 스크립트를 관리한다.

k6 테스트는 클라이언트 관점에서 API 응답 시간, 실패율, 처리량을 측정한다.  
Actuator/Micrometer 지표는 서버 내부 관점에서 HTTP 요청 처리, JVM, DB 커넥션, 커스텀 메트릭을 확인하는 데 사용한다.

즉 두 지표를 함께 보면 다음과 같이 분석할 수 있다.

```text
k6
→ 외부 사용자가 체감하는 응답 시간과 실패율

Actuator/Micrometer
→ 서버 내부 처리량, JVM 상태, DB 커넥션, 커스텀 이벤트 지표
```

## 테스트 파일

```text
backend/src/test/k6/
├── smoke-test.js
└── api-load-test.js
```

### smoke-test.js

주요 조회 API가 정상적으로 응답하는지 빠르게 확인하는 테스트다.

대상 API:

```text
GET /api/v1/logs?page=0&size=20
GET /api/v1/threats?page=0&size=20
GET /api/v1/blacklist?page=0&size=20
```

실행 조건:

```text
가상 사용자: 1명
반복 횟수: 3회
```

통과 기준:

```text
HTTP 요청 실패율 < 1%
p95 응답 시간 < 500ms
```

### api-load-test.js

주요 조회 API에 일정한 부하를 주고 응답 시간과 실패율을 확인하는 테스트다.

부하 패턴:

```text
30초 동안 가상 사용자 10명까지 증가
1분 동안 가상 사용자 10명 유지
30초 동안 가상 사용자 0명까지 감소
```

통과 기준:

```text
HTTP 요청 실패율 < 1%
p95 응답 시간 < 500ms
```

## 실행 전 준비

백엔드 서버가 먼저 실행되어 있어야 한다.

```powershell
cd C:\Projects\2026_kw_capstone_project\backend
.\gradlew bootRun
```

서버 상태 확인:

```text
http://localhost:8080/actuator/health
```

응답 예시:

```json
{
  "status": "UP"
}
```

## 실행 방법

프로젝트 루트에서 실행한다.

```powershell
cd C:\Projects\2026_kw_capstone_project
```

Smoke test 실행:

```powershell
k6 run backend/src/test/k6/smoke-test.js
```

API load test 실행:

```powershell
k6 run backend/src/test/k6/api-load-test.js
```

다른 서버 주소를 대상으로 실행하려면 `BASE_URL` 환경변수를 사용한다.

```powershell
$env:BASE_URL="http://localhost:8080"
k6 run backend/src/test/k6/api-load-test.js
```

## 결과 해석

k6 결과에서 주로 확인할 항목은 다음과 같다.

```text
checks_succeeded
→ check 조건을 통과한 비율

checks_failed
→ check 조건을 실패한 비율

http_req_failed
→ HTTP 요청 실패율

http_req_duration
→ HTTP 요청 응답 시간

p(95)
→ 전체 요청 중 95%가 이 시간 안에 응답했다는 의미

http_reqs
→ 전체 HTTP 요청 수

iterations
→ default function 실행 횟수
```

예시 결과:

```text
checks_succeeded: 100%
checks_failed: 0%
http_req_failed: 0.00%
http_req_duration p(95): 75.67ms
http_reqs: 2457
```

해석:

```text
총 2,457건의 요청이 발생했고,
요청 실패율은 0%였으며,
전체 요청의 95%가 75.67ms 이내에 응답했다.
따라서 설정한 기준인 실패율 1% 미만, p95 500ms 미만을 만족했다.
```

## Actuator 지표와 함께 보기

k6 실행 중 또는 실행 후 다음 Actuator 지표를 함께 확인하면 서버 내부 상태를 분석할 수 있다.

```text
http://localhost:8080/actuator/metrics/http.server.requests
http://localhost:8080/actuator/metrics/hikaricp.connections.active
http://localhost:8080/actuator/metrics/jvm.memory.used
http://localhost:8080/actuator/metrics/process.cpu.usage
```

커스텀 지표:

```text
http://localhost:8080/actuator/metrics/security.blacklist.registrations
http://localhost:8080/actuator/metrics/security.threats.detected
http://localhost:8080/actuator/metrics/security.logs.processed
http://localhost:8080/actuator/metrics/security.kafka.consumer.failures
http://localhost:8080/actuator/metrics/security.log.processing.duration
http://localhost:8080/actuator/metrics/security.ai.request.produced
http://localhost:8080/actuator/metrics/security.ai.request.produce.duration
```

## 현재 테스트 범위

현재 k6 테스트는 읽기 API 중심으로 구성되어 있다.

포함된 범위:

```text
로그 목록 조회
위협 목록 조회
블랙리스트 목록 조회
pagination 조회 API 응답 확인
동시 조회 요청에 대한 기본 부하 테스트
```

포함하지 않은 범위:

```text
Kafka 메시지 입력 부하
AI 분석 요청 전체 파이프라인 부하
블랙리스트 등록 POST 부하
JWT 인증 기반 사용자 시나리오
장시간 soak test
```

쓰기 API나 Kafka 기반 전체 파이프라인 부하 테스트는 DB 데이터 증가와 외부 서비스 의존성이 있으므로 별도 시나리오로 분리한다.

## 로컬 테스트 결과

### Smoke Test

```text
checks_succeeded: 100%
checks_failed: 0%
http_req_failed: 0.00%
http_req_duration p(95): 202.43ms
```

결과:

```text
logs, threats, blacklist 조회 API가 모두 200 OK를 반환했다.
요청 실패율은 0%였고, p95 응답 시간은 500ms 기준을 만족했다.
```

### API Load Test

조건:

```text
최대 가상 사용자: 10명
총 실행 시간: 2분
대상 API: logs, threats, blacklist 조회 API
```

결과:

```text
checks_succeeded: 100%
checks_failed: 0%
http_req_failed: 0.00%
http_req_duration avg: 39.95ms
http_req_duration p(95): 75.67ms
http_reqs: 2457
```

해석:

```text
2분 동안 총 2,457건의 요청을 처리했고 실패 요청은 없었다.
p95 응답 시간은 75.67ms로, 기준값인 500ms보다 낮게 측정되었다.
로컬 환경 기준 주요 조회 API는 최대 10 VU 부하에서 안정적으로 응답했다.
```

## 향후 개선

```text
- Prometheus/Grafana 연동
- Kafka log-topic 입력 부하 테스트 추가
- AI request/response 전체 파이프라인 테스트 추가
- POST /api/v1/blacklist 쓰기 부하 테스트 분리
- JWT 인증 시나리오 추가
- Prometheus/Grafana 연동 후 p95/p99 시각화
- AWS 배포 환경에서 동일 시나리오 재측정
```
