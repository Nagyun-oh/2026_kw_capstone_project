# 로컬 Docker Compose 실행 및 배포 준비

이 문서는 루트 [compose.yaml](../compose.yaml)의 현재 구성을 기준으로 작성했다. 모든 PowerShell 명령은 저장소 루트에서 실행한다. 실제 비밀번호, JWT 키, 개인별 볼륨 이름은 문서에 기록하지 않는다.

AWS에서는 별도 [AWS EC2 배포 및 운영 문서](06_aws_deployment.md)와 `compose.aws.yaml`을 사용한다. 아래 검증 기록은 로컬 전환 당시의 기록이며 AWS 최신 결과와 구분한다.

## 1. 적용 범위

현재 구성은 기존 로컬 데이터를 보존하면서 개별 컨테이너를 `security-platform` Compose 프로젝트로 통합한 구성이다. AWS 배포 완료를 의미하지 않는다.

- 기존 MySQL 데이터 폴더와 스키마가 필요하다. `ddl-auto: validate`이므로 빈 DB에서 테이블을 자동 생성하지 않는다.
- Kafka·Zookeeper 데이터 볼륨과 `security-net`은 `external: true`로 선언돼 있어 사전에 존재해야 한다.
- AI 모델 파일은 Git에 포함되지 않으며 별도로 준비해야 한다.
- Fluent Bit 상태 볼륨은 이번 구성에서 제외했다.
- 각 호스트 포트는 `127.0.0.1`에 바인딩돼 로컬 PC에서 접근한다.

신규 PC나 AWS에서는 저장 공간·DB 스키마·모델을 별도로 준비해야 한다. 기존 로컬 볼륨 이름을 복사하거나 빈 폴더를 만드는 것만으로 기존 환경이 복원되지는 않는다.

## 2. 서비스와 통신 구조

```text
테스트 요청 → WAF → JuiceShop
              ↓ access.log / error.log
           Fluent Bit → Kafka (log-topic / waf-error-topic)
                            ↓
                         Spring Boot → MySQL
                            ↓              ↑
                      ai-request-topic     │
                            ↓              │
                         FastAPI AI        │
                            ↓              │
                       ai-result-topic → Spring Boot
                                            ↓ API / STOMP
브라우저 ← React + Nginx ←───────────────────┘
```

| Compose 서비스 | 컨테이너 이름 | 역할 / 접근 |
| --- | --- | --- |
| `db` | `security-mysql` | MySQL, 호스트 `127.0.0.1:3306`, 내부 `db:3306` |
| `zookeeper` | `zookeeper` | Kafka 메타데이터 관리, 내부 `zookeeper:2181` |
| `kafka` | `kafka` | 호스트 `localhost:9092`, 내부 `kafka:29092` |
| `backend` | `security-backend-local` | Spring Boot, `http://localhost:8080` |
| `frontend` | `security-frontend-local` | React 정적 파일 및 프록시, `http://localhost:3000` |
| `ai` | `security-ai-local` | FastAPI, `http://localhost:8000` |
| `juiceshop` | `juiceshop` | 테스트 대상, 내부 `juiceshop:3000` |
| `waf` | `waf` | 테스트 요청 입구, `http://localhost` |
| `fluent-bit` | `waf-fluent-bit` | WAF 로그를 Kafka로 전송 |

대시보드와 JuiceShop은 서로 다른 화면이다. Nginx는 `/api/`와 `/ws-security`를 백엔드로 전달한다. 로컬·AWS 공통 서비스 이름인 `backend:8080`을 사용해야 하며, 저장소 반영 상태는 AWS 문서의 배포 전 확인 항목을 참고한다. Kafka 내부 주소의 포트는 호스트에 공개하지 않아도 같은 네트워크의 컨테이너끼리 접근할 수 있다.

## 3. 실행 전 준비

### Docker 및 파일

Docker Desktop의 Linux 엔진과 Docker Compose v2가 필요하다.

```powershell
docker info
docker compose version
```

호스트에 Java·Node·Python을 설치하거나 Python 가상환경을 활성화할 필요는 없다. 각 Dockerfile이 빌드·실행 환경을 준비한다.

- 백엔드: Java 17, 기존 Spring 설정의 `prod` 프로파일 사용
- 프론트: Node에서 빌드 후 Nginx로 제공
- AI: `AI_new/`(3모델 앙상블), Python 3.12 계열, `AI_new/requirements.txt` 사용
- AI 모델: 아래 2개 파일 필요 (Git 제외, Kaggle 데이터셋 `hyunwook23/capstone-new2026`에서 받음)
  - `AI_new/models/model_bundle_tree_schema.pkl`
  - `AI_new/models/transformer/model_bundle.pkl` (Kaggle 파일명 `model_bundle.pkl`)
- Kaggle 버전과 SHA-256은 `AI_new/models.lock.json`에 고정돼 있다.
- `attack_taxonomy.json`, `model_bundle.pkl.manifest.json`은 Git에 포함돼 있다.

```powershell
python scripts/fetch_models.py
```

스크립트가 lock에 적힌 버전만 받고 SHA-256이 일치할 때만 저장한다. 이미 받은 파일은 해시만 확인한다. 트랜스포머 번들은 기동 시 매니페스트의 `bundle_sha256`과 비교하므로 해시가 다르면 AI가 기동되지 않는다. 모델 이름만 같다고 코드와 호환된다고 가정하지 않는다.

### 환경 변수

`.env`가 아직 없을 때만 예시를 복사한다. 기존 파일은 덮어쓰지 않는다.

```powershell
if (-not (Test-Path -LiteralPath .env)) {
    Copy-Item -LiteralPath .env.example -Destination .env
}
```

| 변수 | 설정 기준 |
| --- | --- |
| `DB_USERNAME` | 현재 로컬 구성은 `root` 사용 |
| `DB_PASSWORD` | 기존 MySQL에 실제 설정된 root 비밀번호 |
| `MYSQL_DATA_DIR` | 기존 데이터 경로. 현재 기본값은 `./backend/mysql_data` |
| `JWT_SECRET` | 랜덤 32바이트를 Base64로 인코딩한 키 |
| `JWT_EXPIRATION_MS` | 기본값 `86400000` (24시간) |
| `CORS_ALLOWED_ORIGINS` | 현재 대시보드 주소 `http://localhost:3000` |
| `KAFKA_DATA_VOLUME` | 기존 Kafka `/var/lib/kafka/data` 볼륨의 실제 이름 |
| `ZOOKEEPER_DATA_VOLUME` | 기존 Zookeeper `/var/lib/zookeeper/data` 볼륨의 실제 이름 |
| `ZOOKEEPER_LOG_VOLUME` | 기존 Zookeeper `/var/lib/zookeeper/log` 볼륨의 실제 이름 |

`.env.example`의 키·비밀번호·볼륨 이름은 실행 가능한 실제 값이 아니다. 현재 Compose는 `DB_PASSWORD`를 MySQL 초기 root 비밀번호와 백엔드 접속 비밀번호에 함께 사용한다. 별도 앱 계정으로 전환할 때는 설정도 분리해야 한다. 기존 DB에서는 `.env` 수정만으로 계정 비밀번호가 변경되지 않는다.

JWT 키가 없다면 아래 명령으로 생성해 클립보드에 복사한 뒤 `.env`의 `JWT_SECRET`에 붙여넣는다. 이후 같은 값을 재사용한다. 키를 바꾸면 이전 키로 발급한 토큰은 유효하지 않다.

```powershell
$keyBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($keyBytes)
$rng.Dispose()
$jwtSecretForCompose = [Convert]::ToBase64String($keyBytes)
Set-Clipboard -Value $jwtSecretForCompose
```

PowerShell 환경 변수는 `.env`보다 우선한다. 예전 세션 값이 남아 있다면 새 터미널을 사용하거나 해당 세션 변수만 제거한다.

```powershell
Remove-Item Env:DB_USERNAME, Env:DB_PASSWORD, Env:JWT_SECRET, Env:MYSQL_DATA_DIR -ErrorAction SilentlyContinue
```

실제 `.env`는 Git에 올리지 않는다. 아래 첫 명령은 `.env`를 출력하고, 두 번째는 아무것도 출력하지 않아야 한다.

```powershell
git check-ignore .env
git ls-files -- .env
```

### 데이터와 네트워크

이름 변경 전 컨테이너가 남아 있는 환경에서는 다음과 같이 실제 저장 위치를 확인한다. 이미 이름을 변경했다면 `*-before-compose` 이름으로 조회한다.

```powershell
docker inspect security-mysql kafka zookeeper --format '{{.Name}} {{json .Mounts}}'
docker volume ls
docker network inspect security-net
```

MySQL은 `Destination=/var/lib/mysql`의 `Source`를, Kafka·Zookeeper는 데이터 목적지에 대응하는 `Name`을 확인한다. `/etc/.../secrets` 볼륨을 데이터 볼륨과 혼동하지 않는다. `security-net`만 없다면 `docker network create security-net`으로 준비할 수 있지만, 기존 데이터 볼륨이 없는 문제를 빈 볼륨 생성으로 해결하지 않는다.

## 4. 최초 Compose 전환

이미 전환을 완료한 환경은 이 절차를 반복하지 않고 다음 절의 일상 실행 명령을 사용한다.

1. 현재 데이터 백업과 실제 마운트 경로를 확인한다.
2. 아래 명령으로 문법 검증 및 애플리케이션 이미지 빌드를 완료한다.
3. 기존 관련 컨테이너를 중지하고 종료 상태를 확인한다.
4. 같은 이름을 새 Compose에서 사용하도록 기존 컨테이너의 이름을 변경한다.
5. 새 구성을 실행한 뒤 실제 마운트·DB 테이블·애플리케이션 기동을 확인한다.

```powershell
docker compose --env-file .env -f compose.yaml config --quiet
$LASTEXITCODE
docker compose --env-file .env -f compose.yaml build backend frontend ai
docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
```

문법 검증 결과 `0`은 설정 해석 성공만 의미한다. 이미지 존재, DB 데이터, 모델 호환성, 서비스 연결까지 보장하지 않는다. 오류가 있으면 이후 단계로 진행하지 않는다.

이번 전환에서는 기존 6개 컨테이너가 모두 종료된 것을 확인한 뒤 아래 이름 변경을 수행했다.

```powershell
docker rename security-mysql security-mysql-before-compose
docker rename zookeeper zookeeper-before-compose
docker rename kafka kafka-before-compose
docker rename juiceshop juiceshop-before-compose
docker rename waf waf-before-compose
docker rename waf-fluent-bit waf-fluent-bit-before-compose
```

개별 실행했던 앱 컨테이너가 남아 있다면 동일하게 이름 충돌을 정리해야 한다. 기존 컨테이너 이름을 보존한 것은 설정 비교용이며, 공유 데이터의 독립적인 백업이 아니다. 기존·신규 MySQL 또는 Kafka·Zookeeper를 동일한 저장 공간에 연결한 상태로 동시에 시작하지 않는다.

## 5. 일상 실행·중지·재빌드

### 전체 실행과 상태 확인

```powershell
docker compose --env-file .env -f compose.yaml up -d --build
docker compose --env-file .env -f compose.yaml ps -a
```

이미지가 준비됐고 코드 변경이 없다면 `--build`를 생략한다. MySQL·Kafka·AI의 healthcheck 통과 여부와 다른 서비스의 실행 상태를 확인한다. 백엔드의 기동은 별도로 확인한다.

```powershell
Invoke-RestMethod -Uri "http://localhost:8080/actuator/health"
Invoke-RestMethod -Uri "http://localhost:8000/health"
```

- 백엔드: `status=UP`
- AI: `model_loaded=True`
- MySQL healthcheck: 인증 및 `SELECT 1` 성공. 테이블 존재까지 확인하지 않음
- Kafka healthcheck: 토픽 조회 성공. 전체 메시지 처리 성공을 의미하지 않음
- AI healthcheck: HTTP 응답 및 모델 로딩 확인. 실제 예측이나 Kafka 처리까지 확인하지 않음
- `service_started`는 애플리케이션 준비 완료를 보장하지 않음

### 로그와 중지

```powershell
docker compose --env-file .env -f compose.yaml logs --tail 100 backend ai fluent-bit
docker compose --env-file .env -f compose.yaml logs --tail 100 -f backend
```

`logs -f`에서 `Ctrl+C`는 로그 추적만 종료한다.

```powershell
docker compose --env-file .env -f compose.yaml stop
```

평소 종료는 `stop`을 사용한다. `down`은 컨테이너를 삭제하므로 현재 Fluent Bit의 내부 읽기 위치·버퍼도 없어질 수 있다. `down -v`나 volume prune을 데이터 정리 명령으로 사용하지 않는다.

### 코드 변경 반영

이미지는 빌드 시점의 코드를 포함한다. 각 명령은 해당 앱을 재빌드하고 변경된 이미지로 컨테이너를 교체·실행한다.

```powershell
docker compose --env-file .env -f compose.yaml up -d --build --no-deps backend
docker compose --env-file .env -f compose.yaml up -d --build --no-deps frontend
docker compose --env-file .env -f compose.yaml up -d --build --no-deps ai
```

위 명령 중 수정한 서비스에 해당하는 것만 실행한다. `--no-deps`는 DB·Kafka 등 의존 서비스가 이미 준비됐다는 전제다. `build`만 실행하면 실행 중인 컨테이너는 교체되지 않는다. 환경 변수·마운트 변경은 `restart`만으로 반영되지 않으며 `up -d`를 통한 재생성이 필요하다.

백엔드 교체 후 Nginx가 이전 주소를 사용해 `502`를 반환한다면 프론트를 재시작한다.

```powershell
docker compose --env-file .env -f compose.yaml restart frontend
```

## 6. 전체 연동 및 재시작 검증

### 재시작 전후 데이터 비교

1. 대시보드에서 로그·위협·블랙리스트 건수와 기존 항목 ID를 기록한다.
2. `stop` 후 `up -d`로 전체 서비스를 다시 시작한다.
3. 컨테이너 상태와 백엔드·AI health 응답을 확인한다.
4. 기존 ID가 계속 조회되는지 확인한다. 자동 요청으로 건수는 증가할 수 있다.

```powershell
docker compose --env-file .env -f compose.yaml stop
docker compose --env-file .env -f compose.yaml up -d
docker compose --env-file .env -f compose.yaml ps -a
```

이는 중지·시작 검증이다. 컨테이너 삭제·재생성이나 DB 백업 복구 검증과 구분한다.

### HTTP 예측 확인

```powershell
$aiTestBody = @{
    method       = "GET"
    url_path     = "/admin"
    query_params = "q=' OR 1=1--"
    body_content = ""
    user_agent   = "Mozilla/5.0"
    ip_address   = "192.0.2.10"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/predict" -Method Post -ContentType "application/json" -Body $aiTestBody
```

`threat_score`가 0~1 범위이며 응답 필드가 존재하는지 확인한다. 특정 점수를 고정 기대하지 않는다. 이 요청만으로 Kafka나 DB 저장을 검증한 것은 아니다.

### WAF부터 대시보드까지 확인

본 프로젝트의 로컬 JuiceShop을 대상으로 식별 가능한 요청을 발생시킨다.

```powershell
$testMarker = "compose-check-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$testQuery = [Uri]::EscapeDataString("$testMarker' OR 1=1--")
Invoke-WebRequest -Uri "http://localhost/rest/products/search?q=$testQuery" -UseBasicParsing |
    Select-Object StatusCode
$testMarker
```

HTTP 오류 응답이어도 WAF 로그가 남을 수 있다. 대시보드의 신규 로그에서 식별자와 로그 ID를 확인한 뒤 같은 ID의 AI 결과 및 백엔드 처리를 확인한다.

```powershell
docker compose --env-file .env -f compose.yaml logs --since 5m ai backend fluent-bit
```

AI 성공 로그 예: `[Kafka AI] result sent. log_id=... score=...`

모델의 판정 기준 미만이면 위협·블랙리스트가 추가되지 않을 수 있다. 해당 결과의 백엔드 처리까지 구분해서 확인한다. 기존 `dev_tools/scripts/e2e_test.py`는 로그 저장 확인용이며 AI 결과 처리를 검증하지 않는다.

## 7. 문제 해결

### 백엔드 재시작 반복 / `missing table [admin_users]`

```powershell
docker inspect security-backend-local --format 'Status={{.State.Status}} RestartCount={{.RestartCount}} ExitCode={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}}'
docker logs --tail 200 security-backend-local
docker inspect security-mysql-before-compose security-mysql --format '{{.Name}} {{json .Mounts}}'
docker exec -it security-mysql mysql -u root -p
```

MySQL 프롬프트에서 조회한다.

```sql
SHOW DATABASES;
SHOW TABLES FROM security_db;
SELECT TABLE_SCHEMA, TABLE_NAME
FROM information_schema.TABLES
WHERE TABLE_NAME IN ('admin_users', 'network_logs');
exit;
```

이번 전환에서는 새 MySQL이 `backend/mysql_data` 대신 `backend/MYSQL_DATA_DIR`를 연결했다. DB 연결은 성공했지만 기존 테이블이 없는 DB에 연결돼 JPA 검증이 실패했다.

해결 시 백엔드·DB를 중지하고 `.env`의 `MYSQL_DATA_DIR=./backend/mysql_data` 및 셸 환경 변수 우선순위를 확인했다. 아래 명령은 비밀값을 포함한 전체 설정 대신 실제 마운트만 출력한다.

```powershell
$composeCheck = docker compose --env-file .env -f compose.yaml config --format json | ConvertFrom-Json
$composeCheck.services.db.volumes | Select-Object type, source, target
```

기존 경로를 확인한 후 DB를 재생성하고 테이블 확인 후 백엔드를 실행했다. 경로 확인 없이 아래 재생성 명령부터 실행하지 않는다.

```powershell
docker compose --env-file .env -f compose.yaml stop backend db
# 여기서 경로 수정 및 최종 적용 경로 확인
docker compose --env-file .env -f compose.yaml up -d --no-deps --force-recreate db
# 여기서 기존 테이블 확인
docker compose --env-file .env -f compose.yaml up -d backend
```

`ddl-auto`를 `create`로 바꾸거나 기존 폴더를 삭제하지 않았다. `create_host_path: false`는 없는 경로의 자동 생성을 막지만, 이미 존재하는 잘못된 폴더까지 판별하지는 못한다. 잘못 생성된 `backend/MYSQL_DATA_DIR/`는 실행 소스가 아니므로 커밋하지 않는다. 정리는 복구 확인 후 별도로 판단한다.

### AI `KeyError: 'url_path'`, `'url_len'`

> 이전 `AI/`(단일 모델) 기준 사례다. 현재 배포 대상인 `AI_new/`에는 해당하지 않는다.

모델 로딩 성공 이후 피처 생성 단계에서 실패한 사례다. 현재 번들의 `features`는 23개이며 인코더는 `method`, `user_agent`, `url_path`, `file_extension`이다. `build_feature_row()`에서 일부 항목이 주석 처리돼 후속 인코딩·피처 선택 과정에서 키를 찾지 못했다.

```powershell
docker exec security-ai-local python -c "import joblib; b=joblib.load('/app/model_bundle_ultimate.pkl'); print('features:', b.get('features')); print('encoders:', list((b.get('encoders') or {}).keys()))"
```

모델이 요구하는 계산값 반환을 복원하고 AI를 재빌드했다. 입력을 임의의 0으로 채우거나 모델의 피처 목록을 삭제하지 않는다. 팀원과 학습·추론 전처리 일치 여부를 확인하고 실제 예측·Kafka 결과 전송을 재검증한다. 자동 커밋된 실패 메시지는 재시작만으로 다시 처리된다고 보장할 수 없으므로 새 요청으로 검증한다.

### 기타 증상

| 증상 | 확인할 항목 |
| --- | --- |
| `NoBrokersAvailable` | Kafka health, 같은 네트워크, AI의 환경 변수 연결 및 최신 이미지 |
| `WeakKeyException` | JWT 키가 Base64 디코딩 후 최소 32바이트인지 확인 |
| `external volume ... not found` | 실제 기존 볼륨 이름과 `.env` 비교 |
| 컨테이너 이름 충돌 | 기존 컨테이너 상태·이름 확인. 데이터를 지우는 것으로 해결하지 않음 |
| `mapping values are not allowed` | 오류 줄과 앞줄의 들여쓰기 및 `external: true`처럼 콜론 뒤 공백 확인 |
| `no such service: build` | `up -d build`가 아닌 `up -d --build` 사용 |
| PowerShell HTTP 명령 실패 | `Invoke-RestMethod` 철자와 URL 확인. Markdown 링크 표기 대신 URL 문자열만 입력 |

## 8. 현재 검증 기록과 제한 사항

2026-09-22 사용자 실행 결과를 바탕으로 기록했다. 문서 작성 시점에 Docker 실행을 새로 수행한 결과는 아니다.

| 항목 | 확인 상태 |
| --- | --- |
| Compose 문법 검증 | `config --quiet` 종료 코드 0 확인 |
| 앱 이미지 3개 빌드 및 전체 9개 서비스 기동 | 확인 |
| MySQL 경로 수정 후 백엔드 health | `UP` 확인 |
| AI 피처 누락 수정 후 대시보드 | 원본 로그와 연결된 AI 탐지·블랙리스트 표시 및 사용자 동작 확인 |
| 최종 수정 후 전체 중지·시작 및 기존 ID·새 요청 검증 | 절차 안내 완료, 최종 결과 기록 필요 |
| AWS 배포 | 이 로컬 기록 시점에는 미진행. 이후 결과는 [AWS 문서](06_aws_deployment.md) 참고 |

- 현재 루트 Compose에는 Fluent Bit 상태 볼륨이 없다. 단순 중지·시작에는 내부 파일이 남지만 컨테이너 재생성 시 읽기 위치·버퍼를 잃을 수 있다. `Read_from_Head True`에 따라 기존 로그 재수집 및 중복 저장 가능성이 있다. 별도 `waf/docker-compose.yml`에는 상태 볼륨이 있으므로 두 구성을 혼동하지 않는다.
- WAF는 `DetectionOnly`다. 대시보드 블랙리스트 등록과 WAF의 실제 차단은 별개이며 자동 연계는 아직 없다.
- AI 수정 사항이 로컬에만 남아 있으면 GitHub 코드로 같은 결과를 재현할 수 없다. 배포 전 팀원과 확인해 필요한 환경 변수 연결·피처 수정 사항을 반영한다.
- Kafka는 단일 브로커·ZooKeeper 기반이다. KRaft 전환은 데이터 보존 여부와 업그레이드 경로를 정해 별도로 수행한다.

## 9. AWS 배포 전 준비

아래는 로컬 전환 당시의 준비 목록이다. 실제 완료 상태와 남은 작업은 [AWS 문서](06_aws_deployment.md)를 기준으로 확인한다.

현재 파일을 그대로 AWS용 최종 구성으로 사용하지 않는다.

- [ ] MySQL을 신규 초기화할지, 백업을 복원할지 결정하고 스키마 준비 (`validate` 유지).
- [ ] AWS의 데이터 경로, Kafka·Zookeeper 볼륨, 네트워크를 준비. 로컬 볼륨 식별자는 AWS에 존재하지 않음.
- [ ] AI 모델 및 호환되는 코드·의존성 버전을 함께 준비.
- [ ] AWS용 DB 비밀번호·JWT 키 관리, 앱 DB 계정 권한 분리.
- [ ] 외부 접근 주소에 맞춰 CORS·포트 바인딩·보안 그룹 구성. DB·Kafka를 외부 공개하지 않음.
- [ ] 인증 보호 범위를 검토하고 첫 테스트 배포는 접근 대상을 제한.
- [ ] WAF·JuiceShop을 AWS 테스트 구성에 포함할지 결정.
- [ ] Fluent Bit 상태 보존과 로그 보관·중복 처리 방침을 보안 담당자와 확정.
- [ ] 이미지 버전 고정 및 취약점 점검, 백업·복구 절차 확인.
- [ ] 수동 배포 및 전체 연동 검증 후 CI/CD 자동화.

## 참고

- [Docker Compose 시작 순서](https://docs.docker.com/compose/how-tos/startup-order/)
- [Docker Compose 볼륨](https://docs.docker.com/reference/compose-file/volumes/)
- [프로젝트 WAF 문서](../waf/README.md)
- [AI 서버 문서](../AI_new/README.md)
