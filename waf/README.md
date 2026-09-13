# WAF (Web Application Firewall)

OWASP ModSecurity CRS + Nginx 기반 WAF 설정입니다.

## 구조

```text
waf/
  docker-compose.yml              # WAF 컨테이너 및 CRS 환경변수 설정
  rules/
    CUSTOM-001-ai-align.conf      # AI 모델 특성과 맞춘 커스텀 룰
    CUSTOM-002-blacklist.conf     # IP 블랙리스트 룰
  logs/                           # Nginx access/error 로그
  fluent-bit.conf                 # access.log/error.log -> Kafka 전송 설정
  parsers.conf                    # Nginx access.log/error.log 파서
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

WAF는 `/var/log/nginx/access.log`에 요청 로그를 남기고, `/var/log/nginx/error.log`에 Nginx 오류와 ModSecurity 탐지 상세 로그를 남깁니다. 두 경로는 호스트의 `waf/logs/` 폴더와 연결되어 있고, Fluent Bit가 각 파일을 읽어서 Kafka로 전송합니다.

```text
WAF/Nginx access.log -> Fluent Bit -> Kafka topic(log-topic)
WAF/Nginx error.log  -> Fluent Bit -> Kafka topic(waf-error-topic)
```

확인 명령:

```bash
curl "http://localhost/rest/products/search?q=test"
docker exec kafka kafka-console-consumer --bootstrap-server localhost:9092 --topic log-topic --from-beginning --timeout-ms 8000 --max-messages 5
docker exec kafka kafka-console-consumer --bootstrap-server localhost:9092 --topic waf-error-topic --from-beginning --timeout-ms 8000 --max-messages 5
```

## 로그 보관과 교체: 1단계

이번 단계는 수집 상태 영속화와 원본 보관 기능을 제공한다. **자동 삭제와 압축은 구현하지 않았다.** 저장소를 받는 것만으로 예약 작업이 설치되지는 않는다. `modsec_audit.log`는 교체 대상이 아니다. Docker 자체 출력 로그의 자동 삭제 정책도 이번에는 추가하지 않는다.

현재 개발 환경에는 2026-09-06에 수집기 설정을 적용하고 로그를 1회 교체했다. `jinseob` 사용자의 crontab에 KST 매일 00:00/12:00 교체를 등록했으며 출력은 `waf/logs/rotation-scheduler.log`에 누적한다. WSL과 Docker가 실행 중일 때 동작한다. `crontab -l`로 확인하고, 중지하려면 `crontab -e`에서 해당 WAF 작업 줄만 주석 처리한다. 이 호스트 설정은 Git으로 다른 PC에 전달되지 않는다.

- `fluent-bit-state` named volume에 입력별 SQLite 읽기 위치와 파일시스템 버퍼를 저장한다. `DB.sync Full`, `storage.sync full`을 사용한다.
- 두 Kafka 출력은 재시도 소진과 메시지 시간 만료를 피하도록 설정한다. 토픽 이름과 메시지 포맷은 유지한다.
- `access.log`, `error.log`를 교체할 때 `logs/archive/<UTC 시각>-<프로세스 ID>/`로 이동한 뒤 Nginx 로그를 다시 연다. 원본 내용은 비우지 않는다.
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

- `MODSEC_RULE_ENGINE=DetectionOnly`: ModSecurity 탐지 및 차단 활성화
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

차단할 IP를 수동 또는 백엔드 연동으로 추가할 수 있는 블랙리스트 룰 파일입니다.

```apache
SecRule REMOTE_ADDR "@ipMatch 1.2.3.4" \
    "id:20001,phase:1,deny,status:403,log,msg:'Blacklisted IP'"
```

## 미구현 또는 TODO

- [ ] 백엔드 블랙리스트 자동 동기화 (`BlacklistService` -> `CUSTOM-002`)
- [ ] AI 모델 분석 결과와 WAF 정책 자동 연계
