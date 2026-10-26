# WAF (Web Application Firewall)

OWASP ModSecurity CRS + Nginx 기반 WAF 설정입니다.

## 구조

```text
waf/
  docker-compose.yml              # WAF 컨테이너 및 CRS 환경변수 설정
  rules/
    CUSTOM-001-ai-align.conf      # AI 모델 특성과 맞춘 커스텀 룰
    CUSTOM-002-blacklist.conf     # 수동 IP 블랙리스트 룰
    CUSTOM-003-blacklist-sync.conf # 백엔드 블랙리스트 자동 동기화 룰(Include)
  sync/
    blacklist-sync.sh             # 백엔드 블랙리스트 -> ModSecurity 차단 룰 동기화
    99-blacklist-sync.sh          # WAF 시작 훅(/docker-entrypoint.d), 동기화 루프 실행
  tests/                          # 로그 교체·블랙리스트 동기화 단위 테스트
  logs/                           # Nginx access/error 및 ModSecurity 감사 로그
  fluent-bit.conf                 # access.log/감사 로그 -> Kafka 전송 설정
  waf-detection.lua               # 감사 JSON에서 탐지 필드만 추출
  modsecurity.conf.template       # ModSecurity 거래 ID를 nginx $request_id로 지정
  parsers.conf                    # 로그 파서
  scripts/rotate-logs.sh           # 삭제/압축 없는 로그 교체, --dry-run 지원
  scripts/rotation.cron.example    # 12시간 간격 예약 예시 (기본 비활성)
  MEETING_NOTES.md                 # 백엔드 협의 사항과 적용 전 확인 목록
```

## 실행 방법

```bash
docker compose -f ../backend/docker-compose.yml up -d zookeeper kafka db
docker compose -f ./waf/docker-compose.yml -f ../targets/juiceshop/docker-compose.yml up -d
```

## 트래픽 흐름

기본 백엔드 연동:

```text
Client -> WAF (port 80) -> Spring Boot (port 8080)
```

Juice Shop 테스트 타깃 사용 시:

```text
Client -> WAF (port 80) -> Juice Shop (port 3000)
```

## 로그 파이프라인

Nginx는 `/var/log/nginx/access.log`에 완료된 요청을 기록합니다. ModSecurity는 `RelevantOnly` 감사 JSON을 `/var/log/nginx/waf-audit.log`에 기록합니다. 이 파일에는 규칙 탐지 외에 관련 HTTP 오류도 들어올 수 있으므로, Fluent Bit의 Lua 필터가 규칙 ID가 있는 요청만 선별하고 요청·응답 본문, 헤더, 쿼리 문자열을 제거합니다. `/var/log/nginx/error.log`는 Nginx 운영 오류용으로 남겨두며 Kafka로 보내지 않습니다.

```text
WAF/Nginx access.log -> Fluent Bit -> Kafka topic(log-topic) -> AI 분석
ModSecurity waf-audit.log -> Fluent Bit 탐지 필터 -> Kafka topic(waf-detection-topic)
```

### 요청 ID (`request_id`)

같은 요청의 `access.log`와 탐지 이벤트를 연결하려고 두 곳에 같은 ID를 남깁니다.

- `nginx-logging.conf.template`: access.log JSON에 `"request_id":"$request_id"`를 추가합니다. Fluent Bit 설정 변경 없이 `log-topic` 메시지에 포함됩니다.
- `modsecurity.conf.template`: `modsecurity_transaction_id "$request_id";`로 ModSecurity의 `unique_id`를 nginx `$request_id`와 같게 만듭니다. 이 설정이 없으면 `unique_id`가 `179221680893.343331` 같은 별도 값이 되어 서로 연결할 수 없습니다. `waf-detection-topic`의 `request_id`는 이 `unique_id`입니다.

이 이미지는 `conf.d/modsecurity.conf.template`을 기본 제공하므로, 같은 경로로 마운트해 덮어씁니다. 마운트를 추가했으므로 적용하려면 `restart`가 아니라 컨테이너 재생성이 필요합니다.

```bash
docker compose -f waf/docker-compose.yml -f targets/juiceshop/docker-compose.yml up -d --force-recreate waf
```

ID는 변경 적용 이후의 새 요청부터 붙고, 기존 로그에는 없습니다. 같은 값인지 확인하는 방법:

```bash
curl -H "X-Sample-Id: t1" "http://localhost/rest/products/search?q=%27%20OR%20%271%27%3D%271"
grep t1 waf/logs/access.log      # request_id
grep t1 waf/logs/waf-audit.log   # transaction.unique_id (같은 값이어야 함)
```

확인 명령:

```bash
curl "http://localhost/rest/products/search?q=test"
docker exec kafka kafka-console-consumer --bootstrap-server localhost:9092 --topic log-topic --from-beginning --timeout-ms 8000 --max-messages 5
docker exec kafka kafka-console-consumer --bootstrap-server kafka:29092 --topic waf-detection-topic --from-beginning --timeout-ms 8000 --max-messages 5
```

## 로그 보관과 교체: 1단계

이번 단계는 수집 상태 영속화와 원본 보관 기능을 제공한다. **자동 삭제와 압축은 구현하지 않았다.** 저장소를 받는 것만으로 예약 작업이 설치되지는 않는다. 새 `waf-audit.log`는 기존 교체 스크립트의 대상이 아니므로 운영 배포 전에 보관·교체 정책을 정해야 한다. Docker 자체 출력 로그의 자동 삭제 정책도 이번에는 추가하지 않는다.

현재 개발 환경에는 2026-09-06에 수집기 설정을 적용하고 로그를 1회 교체했다. `jinseob` 사용자의 crontab에 KST 매일 00:00/12:00 교체를 등록했으며 출력은 `waf/logs/rotation-scheduler.log`에 누적한다. WSL과 Docker가 실행 중일 때 동작한다. `crontab -l`로 확인하고, 중지하려면 `crontab -e`에서 해당 WAF 작업 줄만 주석 처리한다. 이 호스트 설정은 Git으로 다른 PC에 전달되지 않는다.

- `fluent-bit-state` named volume에 입력별 SQLite 읽기 위치와 파일시스템 버퍼를 저장한다. `DB.sync Full`, `storage.sync full`을 사용한다.
- 두 Kafka 출력은 재시도 소진과 메시지 시간 만료를 피하도록 설정한다. WAF 탐지 토픽은 `waf-detection-topic`이며 기존 `waf-error-topic`의 운영 오류 메시지와 구분한다.
- `access.log`, `error.log`를 교체할 때 `logs/archive/<UTC 시각>-<프로세스 ID>/`로 이동한 뒤 Nginx 로그를 다시 연다. 원본 내용은 비우지 않는다.
- tail 입력의 줄 길이 상한은 `access.log` 512KB, `waf-audit.log` 8MB다. 기본값(32KB)에서는 긴 줄 하나가 파일 감시 전체를 멈췄으므로(`requires a larger buffer size ... Skipping file`), 상한을 넘는 줄은 `Skip_Long_Lines On`으로 그 줄만 건너뛴다. 건너뛴 줄은 Fluent Bit 로그에 `Skipping long lines` 경고로 남는다.
- 보관 파일과 읽기 위치 DB는 Kafka/DB 저장 완료 증명이 아니다. 특히 Kafka 출력의 librdkafka 메모리 큐는 파일시스템 버퍼와 다르므로, 강제 종료 때 미전송 데이터가 자동 복구된다고 보장할 수 없다.

### 최초 적용 주의 사항

`Read_from_Head True`이므로 상태 DB가 없는 최초 실행에는 기존 파일을 처음부터 읽는다. 이미 DB에 저장된 로그가 재전송될 수 있어 백엔드 중복 방지 또는 별도 테스트 환경을 먼저 준비한다. 이 문서의 명령은 준비된 시점에 실행하며, 설정 파일 편집만으로 실행 중인 Fluent Bit에 적용되지는 않는다.

저장소 루트에서 확인 및 적용:

```bash
docker compose -f waf/docker-compose.yml config --quiet
# 백엔드 담당자와 최초 재전송을 협의한 뒤 실행
docker compose -f waf/docker-compose.yml up -d --no-deps fluent-bit
# 파일을 이동하거나 새로 만들지 않는 교체 사전 점검
bash waf/scripts/rotate-logs.sh --dry-run
```

기존에 별도 Compose 프로젝트 이름(`-p`)을 사용했다면 동일한 이름으로 실행해야 기존 서비스와 상태 볼륨을 사용한다. `docker compose down -v`는 상태 볼륨을 지우므로 사용하지 않는다.

### 로그 교체

수집기 설정 적용과 정상 수집을 확인한 뒤 수동 교체할 수 있다.

```bash
bash waf/scripts/rotate-logs.sh
```

스크립트는 `waf`, `waf-fluent-bit` 컨테이너 실행 여부와 Nginx PID를 확인하고 동시 실행을 잠금으로 막는다. 실행 여부만 확인하므로 Kafka 연결이나 수집 완료를 보장하지는 않는다. 실패하면 보관 파일을 유지하고 오류를 반환한다. 파일 이동 후 reopen에 실패한 경우 Nginx가 보관 파일에 계속 기록할 수 있으므로 오류 원인을 해결하고 `docker exec --user 0 waf nginx -s reopen`으로 재열기를 확인한다. 파일을 덮어쓰거나 보관 파일을 삭제하지 않는다.

`Rotate_Wait 60`은 교체된 파일을 추가로 감시하는 시간이다. 보관 폴더를 입력 `Path`에 포함하지 않아 정상 교체 때 재수집을 피한다. **교체 중 수집기 중단, 읽기 지연, 강제 종료가 있으면 보관 파일의 일부를 놓칠 수 있다.** 보관 파일은 유지되지만 자동 재수집되지 않는다. 이후 이벤트 ID·중복 방지 및 별도 재처리 절차를 합의해야 한다.

12시간 주기의 설정 예시는 [rotation.cron.example](scripts/rotation.cron.example)에 있다. 이 파일을 추가하는 것만으로 작업이 등록되지는 않는다. 검증 후 WSL/Linux에서 Docker에 접근 가능한 사용자의 `crontab -e`로 경로를 수정해 등록한다. Windows에서는 WSL과 Docker가 실행 중이어야 한다.

삭제하지 않으므로 `du -sh waf/logs`와 `df -h`로 보관 파일·Docker 볼륨이 위치한 디스크의 여유 공간을 확인한다. Fluent Bit 버퍼에 오래된 데이터를 버리는 용량 제한도 추가하지 않았으므로 장애가 길어지면 디스크가 찰 수 있다.

### 검증 및 다음 단계

로컬 파일을 사용한 교체 스크립트 검증(실제 WAF/로그에 접근하지 않음):

```bash
python3 -m unittest discover -s waf/tests -v
```

자동 삭제 활성화 전에는 별도 환경에서 정상 수집, DB/Kafka 중단과 복구, Fluent Bit 재시작, 교체 중 재시작을 검증해야 한다. 백엔드 합의 사항은 [회의 메모](MEETING_NOTES.md)에 정리했다.

참고: [Fluent Bit Tail](https://docs.fluentbit.io/manual/2.2/pipeline/inputs/tail), [파일시스템 버퍼](https://docs.fluentbit.io/manual/2.2/administration/buffering-and-storage), [Kafka 출력](https://docs.fluentbit.io/manual/2.2/pipeline/outputs/kafka), [Nginx 로그 교체](https://nginx.org/en/docs/control.html#logs).

## 현재 설정

CRS 기본 룰셋은 `owasp/modsecurity-crs:nginx` Docker 이미지에 포함되어 있습니다. 프로젝트에서는 `docker-compose.yml`의 환경변수로 CRS 민감도와 차단 임계값을 설정합니다.

```yaml
MODSEC_RULE_ENGINE: DetectionOnly
PARANOIA: 2
BLOCKING_PARANOIA: 1
ANOMALY_INBOUND: 5
ANOMALY_OUTBOUND: 4
```

- `MODSEC_RULE_ENGINE=DetectionOnly`: ModSecurity는 탐지·기록만 하고 차단하지 않는다(WAF·AI 비교 실험용). 블랙리스트 룰(20100)만 `ctl:ruleEngine=On`으로 예외적으로 차단한다.
- `PARANOIA=2`: CRS 탐지 범위를 PL2까지 확장
- `BLOCKING_PARANOIA=1`: 실제 차단 판단은 PL1 기준으로 적용
- `ANOMALY_INBOUND=5`: 요청 이상 점수가 5 이상이면 차단
- `ANOMALY_OUTBOUND=4`: 응답 이상 점수가 3 이상이면 차단

## 커스텀 룰

### CUSTOM-001-ai-align.conf

AI 모델이 사용하는 HTTP 특성과 맞춰 WAF 1차 차단 기준을 추가합니다.

| Rule ID | 대상 | 기준 |
| --- | --- | --- |
| 10001 | HTTP Method | 허용되지 않은 Method 차단 |
| 10002 | URL 길이 | 500자 초과 차단 |
| 10003 | 요청 Body 크기 | 10KB 초과 차단 |
| 10004 | Juice Shop 호환성 | 허용 Method 확장 |
| 10005 | Socket.IO 호환성 | polling 요청의 CRS 오탐 완화 |

SQL Injection, XSS, Path Traversal 같은 일반 웹 공격 패턴은 기본 CRS 룰셋이 담당합니다.

### CUSTOM-002-blacklist.conf

백엔드와 별개로 직접 차단할 IP를 넣는 수동 블랙리스트 룰 파일입니다(id 20001~20099). `DetectionOnly`에서도 차단하려면 `ctl:ruleEngine=On`을 함께 넣습니다.

```apache
SecRule REMOTE_ADDR "@ipMatch 1.2.3.4" \
    "id:20001,phase:1,deny,status:403,log,msg:'Blacklisted IP',ctl:ruleEngine=On"
```

### CUSTOM-003-blacklist-sync.conf

백엔드 블랙리스트를 자동으로 반영하는 룰입니다(id 20100). 아래 [블랙리스트 자동 동기화](#블랙리스트-자동-동기화)를 참고합니다.

## 블랙리스트 자동 동기화

관리자 대시보드의 블랙리스트(백엔드 `ip_blacklist`)를 WAF가 주기적으로 받아 실제 차단 룰로 적용합니다. 백엔드·프론트 코드는 바꾸지 않고, 백엔드의 조회 전용 API(`GET /internal/waf/blacklist`, PR #88)만 사용합니다.

```text
관리자 등록·삭제 / AI 자동 등록 -> MySQL ip_blacklist
WAF 컨테이너 안 blacklist-sync.sh (10초 간격)
  -> GET http://backend:8080/internal/waf/blacklist  (X-WAF-Sync-Token)
  -> 응답 전체 JSON 검증 -> version이 바뀌었을 때만: IP 검증·제외 -> 룰 생성
  -> 이전 룰 백업 -> 교체 -> nginx -t -> reload -> 새 worker 확인 -> 백업 삭제
  -> /var/lib/waf-blacklist/blacklist.conf  (CUSTOM-003이 Include, waf-blacklist-state 볼륨)
차단된 요청 -> 403, 감사 로그의 rule 20100 -> 대시보드 WAF Detection
```

### 구성 요소

| 구성 | 역할 |
| --- | --- |
| `waf-blacklist-init` | WAF보다 먼저 한 번 실행되고 종료한다. 상태 볼륨 소유자를 WAF 실행 계정(101)으로 바꾸고 빈 룰 파일을 만든다. ModSecurity v3는 `IncludeOptional`이 없어 Include 대상이 없으면 WAF가 시작되지 않기 때문이다. |
| `99-blacklist-sync.sh` | 이미지의 `/docker-entrypoint.d` 훅. 저장된 룰 형식을 확인(`prepare`)하고 동기화 루프(`run`)를 백그라운드로 띄운다. 실행 권한(755)이 있어야 실행된다. |
| `blacklist-sync.sh` | 조회·검증·적용 본체. 응답은 WAF 이미지에 포함된 perl `JSON::PP`로 해석한다. 로그는 `docker logs waf`에 `[blacklist-sync]`로 남는다. |
| `waf-blacklist-state` 볼륨 | 마지막으로 적용에 성공한 룰. 재시작·재생성 직후 백엔드 연결 전에도 이전 차단을 유지한다. 적용 중에만 `blacklist.conf.prev`(교체 전 마지막 정상 룰)가 함께 있다. |

`MODSEC_RULE_ENGINE=DetectionOnly`에서는 `deny`가 실행되지 않는다. 생성 룰에 `ctl:ruleEngine=On`을 넣어 **블랙리스트에 걸린 요청만** 차단하고, 나머지 CRS 판정은 계속 탐지만 한다.

### 설정

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `WAF_SYNC_TOKEN` | 없음 | 백엔드와 같은 값(32자 이상). 비어 있으면 동기화하지 않고 저장된 룰만 쓴다. 생성: `openssl rand -hex 32` |
| `WAF_SYNC_INTERVAL` | `10` | 조회 간격(초) |
| `WAF_SYNC_EXCLUDE_IPS` | 없음 | 절대 차단하지 않을 추가 IP(쉼표 구분, 단일 IP만) |
| `WAF_RELOAD_TIMEOUT` | `10` | reload 뒤 새 worker로 바뀌었는지 기다리는 시간(초). 느린 서버에서만 늘린다 |

다음 IP는 백엔드 목록에 있어도 차단하지 않고 로그에 남긴다.

- `0.0.0.0`, `::`, `127.0.0.0/8`, `::1`
- 컨테이너 기본 게이트웨이(자동 감지): 로컬에서는 호스트에서 보낸 모든 요청, AWS에서는 호스트 Nginx의 출발지다(로컬 `172.20.0.1`, AWS 예시 `172.18.0.1`).
- `SET_REAL_IP_FROM`이 단일 IP일 때 그 값(AWS의 `WAF_TRUSTED_PROXY`)
- 형식이 틀린 값(CIDR, `::ffff:1.2.3.4` 같은 IPv4 포함 IPv6 표기 등)

### 실패 시 동작

| 상황 | 동작 |
| --- | --- |
| 백엔드 중지·연결 실패·401·500 | 기존 룰 유지. 같은 오류는 처음 한 번만 기록하고 복구되면 `동기화 복구`를 남긴다. |
| JSON 문법 오류, 필드 누락, 타입 불일치(문자열이 아닌 IP·version 등) | 응답 전체를 JSON으로 해석해 확인한다. 깨진 응답 안에 빈 배열이 있어도 기존 룰을 유지한다(차단 해제 안 함). 다른 필드가 더 있는 것은 허용한다. |
| 정상 응답(200)의 빈 목록 | 차단할 IP가 없는 것으로 보고 기존 차단 해제 |
| 이전 룰 백업·파일 교체 실패 | 기존 룰 유지. 실패한 목록의 version을 기억하지 않으므로 다음 주기에 다시 적용한다. |
| `nginx -t` 실패, reload 신호 전송 실패 | 이전 룰로 되돌리고 다음 주기에 다시 적용 |
| reload 신호 후 새 worker 확인 시간 초과 | 새 룰이 이미 적용됐을 수 있으므로 이전 룰로 되돌린 뒤 **다시 검증·reload**해 실제 nginx 설정을 파일과 맞춘다. 다음 주기에 같은 목록이어도 다시 적용한다. |
| 적용 도중 종료(`blacklist.conf.prev`가 남음) | 교체된 룰은 검증·reload 전일 수 있으므로, 재시작(`prepare`)이나 다음 동기화 때 `.prev`(마지막 정상 룰)로 되돌린 뒤 다시 적용한다. |
| WAF 재시작·재생성 | 볼륨의 마지막 정상 룰로 시작한 뒤 최신 목록으로 재동기화 |
| 저장된 룰 형식이 깨짐 | `blacklist.conf.invalid`로 옮기고 빈 룰로 시작 |

### 확인 명령

```bash
docker logs waf 2>&1 | grep blacklist-sync                         # 동기화 기록
docker exec waf cat /var/lib/waf-blacklist/blacklist.conf          # 현재 적용 룰
docker exec waf bash /opt/waf-blacklist/blacklist-sync.sh once     # 즉시 한 번 동기화
python3 -m unittest discover -s waf/tests -v                       # 단위 테스트(Docker 불필요, CI에서도 실행)
```

로컬에서 호스트가 보낸 요청은 게이트웨이 IP라 차단 대상에서 빠진다. 403을 직접 확인하려면 같은 네트워크의 다른 컨테이너에서 요청하고, 그 컨테이너 IP(`172.x`)를 관리자 API `POST /api/v1/blacklist`로 등록한다. `127.x`로 잘못 입력하면 제외 대상이라 403이 나오지 않는다.

```bash
docker inspect security-ai-local -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
docker exec security-ai-local python -c "import urllib.request; print(urllib.request.urlopen('http://waf:8080/').status)"
```

### 검증 결과 (로컬)

**2026-10-20**

- 등록 후 약 4초 안에 해당 IP 403, 삭제 후 다음 주기에 200 복구
- 같은 시점 호스트(게이트웨이) 요청과 관리자 대시보드(WAF를 거치지 않음)는 200 유지
- 목록 밖 IP의 SQLi는 차단되지 않고 CRS 탐지만 기록(`DetectionOnly` 유지)
- WAF 재시작, 백엔드가 꺼진 상태의 WAF 재생성 직후에도 차단 유지. 백엔드 복구 후 자동 재동기화

**2026-10-21** (관리자 API 등록, 대시보드 삭제로 재검증)

| 시각(UTC) | 동작 | 결과 |
| --- | --- | --- |
| 04:12:46 | 관리자 API로 `172.20.0.7` 등록 | 04:12:49 `적용 완료: 추가 [172.20.0.7]` (3초) |
| 04:12:56 | 해당 컨테이너에서 WAF 요청 | 403 |
| 04:13:36 | 대시보드에서 삭제 | 04:13:43 `적용 완료: 해제 [172.20.0.7]` (7초) |
| 04:13:50 | 같은 요청 | 200 |

- 차단 중 호스트(게이트웨이) 요청과 대시보드는 200 유지
- `127.0.0.7`, `127.20.0.7` 등록 시 백엔드에는 저장되지만 WAF는 `차단하면 안 되는 IP라서 제외`로 기록하고 차단하지 않음
- 백엔드가 약 1시간 50분 동안 기동하지 못한 상태(DB 미기동)에서 기존 룰 유지. 백엔드 복구 후 `동기화 복구: 실패 635회 뒤 정상 조회`로 자동 재동기화
- 삭제 후 같은 IP가 다시 등록되지 않음. 단, 시험 요청이 공격이 아닌 `GET /`라 아래 재등록 한계는 검증하지 않음

**2026-10-21** (실패 처리 보완, 실제 nginx로 reload 확인 시간 초과 재현)

일회용 WAF 컨테이너에서 기존 worker를 `SIGSTOP`으로 멈춰, nginx master는 새 룰을 읽었지만 스크립트의 worker 교체 확인은 시간 초과되는 상황을 만들었다. 차단 대상 클라이언트를 등록한 뒤 worker를 다시 실행하고 결과를 비교했다.

| 스크립트 | 룰 파일 | 실제 응답 | 판단 |
| --- | --- | --- | --- |
| 보완 전 | 클라이언트 IP 없음(파일만 되돌림) | 403(새 룰이 적용돼 있음) | 불일치 |
| 보완 후 | 클라이언트 IP 없음 | 통과(이전 룰로 다시 reload) | 일치 |

파일 교체 실패, 적용 중 종료 후 재시작, 깨진 JSON 수신은 `waf/tests/test_blacklist_sync.py`의 회귀 테스트로 재현한다. 보완 전 스크립트에서는 추가한 테스트 7개가 모두 실패한다.

### 한계

- **만료 없음**: 스냅샷 API가 IP만 주므로 WAF는 `expiredAt`을 알 수 없다. 관리자가 삭제해야만 해제된다. (백엔드 정책 필요)
- **차단된 요청의 재수집과 삭제 직후 재등록**: 차단된 요청(403)도 access 로그로 저장·AI 분석된다(`processWafAccessJson`에는 블랙리스트 확인이 없음). 차단 중에는 백엔드의 중복 확인으로 블랙리스트 행은 늘지 않지만, 요청마다 로그·AI 탐지·알림은 쌓인다. 분석은 비동기라 삭제 전에 들어온 공격 요청의 AI 결과가 삭제 후 도착해도 다시 등록되며, 삭제 후 다음 동기화 전(최대 `WAF_SYNC_INTERVAL`초)의 공격 요청도 같다. (백엔드 정책 필요)
- **제외 IP만 바뀌어도 reload**: 룰 파일에 백엔드 version을 주석으로 남기므로, 실제 차단 IP가 같아도 목록이 바뀌면 파일을 다시 쓰고 reload한다. 동작에는 영향이 없다.
- **반복 실패 로그**: 백엔드가 재시작을 반복하면 연결 오류 종류(이름 조회 실패·연결 거부)가 번갈아 바뀌어 같은 실패가 주기적으로 다시 기록된다.
- **IPv6 표기**: 소문자 변환만 하고 축약 형태를 정규화하지 않는다. 같은 주소를 다른 표기로 등록하면 서로 다른 값으로 본다.

## 미구현 또는 TODO

- [x] 백엔드 블랙리스트 자동 동기화 (`/internal/waf/blacklist` -> `CUSTOM-003`)
- [ ] 차단 만료(`expiredAt`) 반영과 삭제 직후 재등록 방지 (백엔드 정책)
- [ ] AI 모델 분석 결과와 WAF 정책 자동 연계
