# 부하·지연 측정 (T3·T4)

메인 스택(`compose.yaml`)에서 네 가지를 잰다.

| 측정 | 내용 | 스크립트 |
| --- | --- | --- |
| 사용자 응답 지연 (T4) | 같은 정상 요청을 JuiceShop에 직접 보낼 때와 WAF를 거칠 때의 응답 시간 p50·p95·p99 | `run-latency.sh`, `analyze_latency.py` |
| 자원 사용량 (T3) | 위 측정 동안 컨테이너별 CPU·메모리(`docker stats`, 약 1초 간격) | `run-latency.sh`, `analyze_latency.py` |
| 탐지 지연 (T4) | 공격 요청을 보낸 시각부터 위협이 DB에 저장될 때까지, Kafka 기록 시각으로 단계를 나눈다 | `run-detection.sh`, `detection_latency.py` |
| AI 처리량 | AI 호출 방식·스레드 설정별 초당 처리 건수와 건당 CPU | `ai_threads.py` |

AI는 Kafka로 비동기 처리하므로 사용자 응답 경로에는 WAF만 있다. 그래서 응답 지연은 WAF의 추가 지연을, 탐지 지연은 로그 수집부터 AI 판정까지의 파이프라인 지연을 본다.

## 구성

- 부하 생성: k6(`grafana/k6:1.0.0` 이미지, 설치 불필요). `security-net` 안에서 `juiceshop:3000`(직접)과 `waf:8080`(WAF 경유)으로 보낸다. 같은 네트워크 경로라 차이는 WAF 처리 시간이다.
- 요청 구성(`requests.json`): JuiceShop 첫 화면이 부르는 정상 요청 15종(API 8, 정적 파일 6, 로그인 실패 1). 반복 번호 순서로 보내 두 조건의 요청 구성을 같게 한다.
- 부하: 일정 도착률(constant-arrival-rate) 10·50·100 RPS, 60초씩 3회. 회차마다 직접/WAF 순서를 바꾼다.
- WAF만 구성: `PAUSE_PIPELINE=1`이면 Fluent Bit을 일시 정지해 분석 파이프라인(Kafka·백엔드·AI·MySQL)이 쉬는 상태로 잰다. 끝나면 재개하고, 쌓인 로그는 그대로 처리된다.
- 탐지 지연: AI가 공격으로 판정한 census 공격 샘플 300건(URI 200자 이하)을 초당 2건 보낸다. 정상 부하 없음, 초당 3건, 초당 8건 세 조건이다.

## 실행 (WSL)

```bash
docker restart security-ai-local          # 메인 AI는 여러 스레드에서 호출된 뒤 느려진다(아래 결과 참고)
bash dev_tools/load-test/run-latency.sh    # 약 1시간 40분(AI가 밀린 로그를 처리하는 시간 포함)
python3 dev_tools/load-test/analyze_latency.py dev_tools/datasets/load-test/latency
PAUSE_PIPELINE=1 REPS=1 OUT=dev_tools/datasets/load-test/latency-waf-only bash dev_tools/load-test/run-latency.sh
python3 dev_tools/load-test/analyze_latency.py dev_tools/datasets/load-test/latency-waf-only
bash dev_tools/load-test/run-detection.sh  # 약 20분
python3 dev_tools/scripts/plot_experiment_figures.py   # 그래프: docs/images/experiments/
```

AI 처리량은 메인 스택과 분리한 실험용 AI 컨테이너로 잰다(`ai_threads.py` 머리말 참고). Kafka 경로는 메인 AI를 잠시 멈추고, AI 요청이 쌓인 상태에서 같은 이미지에 `OMP_NUM_THREADS=1`만 준 컨테이너를 붙여 처리 속도를 쟀다(끝난 뒤 메인 AI를 다시 켠다).

```bash
docker stop security-ai-local      # AI 요청이 ai-request-topic에 쌓인다
docker run -d --name ai-omp1 --network security-net --network-alias ai \
    -e KAFKA_BOOTSTRAP_SERVERS=kafka:29092 -e OMP_NUM_THREADS=1 security-ai:local
# ai-service-group lag이 0이 될 때까지 ai-result-topic 기록 시각으로 처리 속도를 잰다
docker rm -f ai-omp1 && docker start security-ai-local
```

결과는 `dev_tools/datasets/load-test/`(Git 제외)에 쌓인다.

## 결과 (2026-10-22, 로컬 PC)

AMD Ryzen 5 7500F(6코어 12스레드), WSL2, Docker. AWS t3.large(2 vCPU, 기준 성능 vCPU당 30%)는 코어 수·속도가 달라 절대값을 그대로 옮길 수 없다.

### 사용자 응답 지연

| RPS | 직접 접속 p50 / p95 | WAF만 p50 / p95 (파이프라인 정지, 1회) | WAF + 파이프라인 p50 / p95 (3회 합산) |
| --- | --- | --- | --- |
| 10 | 3.3 / 38.4ms | 7.2 / 42.9ms | 7.9 / 44.6ms |
| 50 | 2.8 / 36.8ms | 6.7 / 39.9ms | 7.7 / 46.8ms |
| 100 | 3.6 / 72.4ms | 9.2 / 78.2ms | 18.6ms / 8.9초 |

- **WAF 자체가 더하는 지연은 4~6ms다**(p50 기준. 정적 파일은 약 1ms → 5ms). 10·50 RPS에서 회차 간 차이는 p50 0.8ms, p95 3.3ms 이내다. 오류 응답은 0건이다.
- **100 RPS에서 WAF와 분석 파이프라인을 같은 PC에서 함께 돌리면 응답이 수 초까지 늦어졌다**(p95 7.5~10초, 3회 모두). 느려진 요청은 JuiceShop의 DB 조회 API(`/api/Quantitys/`, `/api/Products/1`, 검색, 로그인)뿐이고, 시간이 지날수록 대기열이 커졌다. 파이프라인을 멈추면(WAF만) 생기지 않았다.
- 원인은 CPU 경합이다. 같은 요청량에서 JuiceShop CPU는 직접 0.99코어, WAF만 1.02코어인데 파이프라인과 함께 돌면 1.22코어였다. 100 RPS는 JuiceShop 처리 한계 부근이다(직접 접속에서도 DB API p50 40~70ms). 처음에는 WAF가 JuiceShop 연결을 재사용하지 않는 것(upstream keepalive 없음)을 의심했지만, WAF만 구성에서 CPU가 늘지 않아 주된 원인은 아니었다.
- 100 RPS WAF + 파이프라인 실행에서는 응답이 늦어지면서 k6가 동시 사용자 한도에 걸려 요청의 약 4%를 보내지 못했다.
- AI 스레드를 1개로 바꿔도(아래 개선 후 측정) 10·50 RPS 응답 지연은 같았고(p50 8ms, p95 46~49ms), 100 RPS WAF + 파이프라인은 2회 모두 다시 대기열이 생겼다(p95 7.9~10.6초). AI가 덜 쓰지만 100 RPS에서는 여전히 약 1코어를 쓰고, 백엔드·MySQL·Kafka도 함께 바빠지기 때문이다.
- 100 RPS는 이 PC에서 JuiceShop 처리 한계와 겹친다. 직접 접속 6회 중 5회는 p95 71~78ms였지만 측정 후반 1회는 987ms로 밀렸다(JuiceShop 메모리가 0.3GiB에서 1.2GiB로 늘어난 상태). 앱을 처리 한계 가까이에서 운영한다면 분석 파이프라인은 다른 서버로 나눠야 한다.

### 자원 사용량 (WAF 경유, 평균 CPU 코어)

| 구성요소 | 10 RPS | 50 RPS | 100 RPS | 최대 메모리 (100 RPS) |
| --- | --- | --- | --- | --- |
| JuiceShop (보호 대상 앱) | 0.15 | 0.61 | 1.22 | 1.43GiB |
| WAF (ModSecurity) | 0.05 | 0.23 | 0.44 | 0.17GiB |
| AI | 1.42 | 1.41 | 1.40 | 0.65GiB |
| Kafka | 0.11 | 0.14 | 0.14 | 0.98GiB |
| 백엔드 | 0.03 | 0.10 | 0.15 | 0.46GiB |
| MySQL | 0.03 | 0.10 | 0.16 | 0.35GiB |
| Zookeeper·Fluent Bit | 0.01 | 0.01 | 0.02 | 0.12GiB |

- WAF 단독 대비 추가되는 분석 파이프라인은 CPU 1.6~1.9코어, 메모리 약 2.6GiB다. CPU의 대부분이 AI다.
- AI는 Kafka 메시지를 한 건씩 처리해 **초당 약 5.4건이 한계**였다(1.4코어). 10 RPS만 돼도 처리가 밀린다. WAF 경유 60초 실행 뒤 밀린 로그를 다 처리하는 데 10 RPS 57초, 50 RPS 약 500초, 100 RPS 약 1,000초가 걸렸다.
- JuiceShop 메모리 1.43GiB는 100 RPS에서 대기열이 쌓였을 때 값이다(50 RPS에서는 0.46GiB).

### 탐지 지연 (공격 300건, 초당 2건)

| 조건 | AI 위협 저장까지 p50 / p95 (기본) | AI 위협 저장까지 p50 / p95 (스레드 1개) | CRS(WAF) 위협 저장까지 p50 / p95 |
| --- | --- | --- | --- |
| 공격만 초당 2건 | 0.42 / 0.71초 | 0.26 / 0.26초 | 0.22 / 0.51초 |
| 정상 3 + 공격 2 = 초당 5건 | 0.54 / 0.66초 | 0.50 / 0.51초 | 0.34 / 0.46초 |
| 정상 8 + 공격 2 = 초당 10건 | 76.3 / 138.1초 | 0.36 / 0.37초 | 0.39 / 0.51초 |

- 공격만 보낼 때 단계별 중앙값: WAF 기록 → Kafka(Fluent Bit) 207ms, 백엔드 로그 저장 8ms, AI 요청 발행 1ms 미만, AI 추론 196ms, 위협 저장 4ms.
- 300건 모두 AI 위협으로 저장됐고, 그중 258건은 CRS도 탐지해 감사 로그 경로로 "WAF Detection" 위협이 먼저 저장됐다.
- 들어오는 로그가 AI 처리량(초당 약 5건)을 넘으면 AI 탐지만 대기열만큼 늦어진다. CRS 탐지 경로는 부하와 관계없이 0.5초 안팎이다.
- 스레드 1개로 바꾸면 AI 추론 단계가 196ms에서 16ms(초당 10건에서 35ms)로 줄고, 초당 10건에서도 대기열이 생기지 않았다. 남은 지연의 대부분은 Fluent Bit 수집(0.5초마다 묶어 보냄)이다.

### AI 처리량과 스레드 설정

| 설정 | Kafka 경로 처리량 | CPU | 메시지 1건당 CPU |
| --- | --- | --- | --- |
| 기본(스레드 수 지정 없음) | 5.4건/s | 1.42코어 | 263ms |
| `OMP_NUM_THREADS=1` | 84.0건/s | 0.93코어 | 11ms |

- 같은 이미지·같은 Kafka 경로에서 스레드 수만 바꿨다. 쌓인 요청 9,570건을 113.9초에 처리했다(메시지 간격 중앙값 12ms).
- 실험용 컨테이너 진단(`ai_threads.py`, HTTP): 기본 설정은 묶음 호출 74건/s에 CPU 5.2코어를 썼고, 4개 동시 호출 뒤에는 묶음 호출이 24건/s로 떨어진 채 회복되지 않았다. `OMP_NUM_THREADS=1`은 묶음 71~73건/s(0.9코어), 한 건씩 순차 176건/s였고 느려지지 않았다. 메인 AI가 오래 실행되면 느려지던 현상(`wafs/README.md`)도 여러 스레드(HTTP 요청 처리 스레드, Kafka 처리 스레드)에서 모델을 호출한 뒤 생기는 같은 현상으로 보인다.
- 스레드 1개 AI의 CPU는 부하에 따라 10 RPS 0.16코어, 50 RPS 0.75코어, 100 RPS 0.99코어(한계 초당 84건)였다. 기본 설정은 부하와 관계없이 1.4코어였다. 10 RPS에서 분석 파이프라인 전체의 추가 CPU는 1.6코어에서 약 0.4코어로 준다.
- 개선 후 측정은 메인 AI를 잠시 멈추고 같은 이미지에 `OMP_NUM_THREADS=1`만 준 임시 AI를 붙인 상태에서 `run-latency.sh`(REPS=2)와 `run-detection.sh`를 그대로 돌렸다(결과: `latency-omp1/`, `detection-omp1/`). 끝난 뒤 메인 AI를 원래 설정으로 되돌렸다.
- **AI가 빨라지자 백엔드 경합이 드러났다.** 로그 저장 트랜잭션이 커밋되기 전에 AI 결과가 도착하면 `LogEntry not found`로 결과를 버린다(개선 후 측정 약 1.9만 건 중 1건). AI 설정을 바꿀 때 백엔드도 AI 요청을 커밋 뒤에 보내도록 함께 고쳐야 한다.
- 적용(`compose.yaml`의 AI 환경 변수 또는 코드의 `torch.set_num_threads(1)`)은 AI 팀이 판정 결과가 같은지 확인한 뒤 정한다.

### 측정 중 확인한 것

- **DB 시각이 KST로 저장된다.** 백엔드는 `UtcDateTime.now()`로 UTC를 넘기지만 JDBC 주소의 `serverTimezone=Asia/Seoul`(`compose.yaml`) 때문에 9시간 더해져 저장된다. 앱이 읽을 때는 다시 UTC로 바뀌어 화면에는 문제가 없지만, SQL로 직접 조회·비교하면 9시간 어긋난다. `detection_latency.py`는 Kafka 기록 시각과 비교해 오프셋을 구하고 보정한다.
- WSL2가 Windows와 시계를 맞추면서 시각이 드물게 1~2초 뒤로 간다. 탐지 지연 300건 중 1~6건에서 음수 구간이 생겼고, 중앙값에는 영향이 없다.
- 측정 동안 시험 요청 약 6만 건이 `network_logs`에 저장됐다. 정상 부하는 `raw_log`의 `X-Load-Test` 헤더, 공격 샘플은 `X-Sample-Id: SID-det...`로 구분할 수 있다.

## 주의

- **매 실행 전에 파이프라인이 빌 때까지 기다린다.** AI가 밀린 로그를 처리하는 동안 직접 접속을 재면 그 CPU 사용이 결과에 섞인다. 그래서 WAF 경유 실행 뒤에 밀린 처리가 끝나는 시간(`drain_s`)이 전체 소요 시간의 대부분을 차지한다.
- **요청 목록을 바꾸면 AI 판정을 먼저 확인한다.** 지금 목록은 AI가 모두 정상으로 판정했다(최고 점수 0.18). 오탐이 나면 블랙리스트 자동 등록(점수 0.8 이상)으로 k6 컨테이너 IP가 WAF에서 차단돼 이후 측정이 403으로 깨진다. 실행 스크립트는 블랙리스트 건수가 바뀌면 멈춘다.
- 탐지 지연용 공격 요청은 WAF(DetectionOnly)를 지나 JuiceShop까지 간다. 초당 2건·300건이라 부담은 작지만, 대량으로 보내면 JuiceShop이 메모리 부족으로 종료될 수 있다(`wafs/README.md` 참고). 보내는 쪽(호스트)은 WAF에서 Docker 게이트웨이 IP로 보이고, 이 IP는 블랙리스트 동기화에서 제외된다.
