# AWS EC2 배포 및 운영 절차

## 1. 범위와 검증 기록

단일 EC2에서 [compose.aws.yaml](../compose.aws.yaml)로 9개 서비스를 실행하는 개발·시연 환경이다. 로컬 전용 [compose.yaml](../compose.yaml)과 혼합해서 실행하지 않는다.

2026-09-26 사용자가 제공한 CLI 출력과 동작 확인을 기준으로 기록했다. 문서 작성 과정에서 EC2 작업을 다시 실행한 것은 아니다.

| 항목 | 확인 결과 |
| --- | --- |
| Docker Engine·Compose 및 앱 이미지 준비 | 전체 서비스 기동으로 확인 |
| AI 모델 전달 | 로컬·EC2 SHA-256 일치 |
| 실제 환경변수 구성 검증 | `config --quiet` 종료 코드 0 |
| 신규 MySQL 초기화 | 테이블 6개, 핵심 테이블 4개 각각 0건 확인 |
| 서비스 연결 | 백엔드 health UP, AI model_loaded=true, WAF HTTP 200 |
| 외부 접근 | 허용한 팀원 공인 IP에서 대시보드 접근 확인 |
| 처리 흐름 | 로그 조회, 동일 logId의 AI 요청·결과 수신, 탐지·블랙리스트 표시 확인 |
| EC2 중지·시작 | 사용자가 기존 데이터 보존 및 새 요청 처리 확인 |
| 자동 기동·백업 복구·부하 테스트 | 별도 검증 필요 |

현재 관리 API 인증이 열려 있어 보안 그룹으로 접근 대상을 제한한다. WAF는 `DetectionOnly`이며 블랙리스트 표시가 실제 WAF 차단을 의미하지 않는다. 공개 운영 서비스 수준의 인증·HTTPS·고가용성 검증 완료를 의미하지 않는다.

## 2. EC2 준비

| 항목 | 이번 배포 기준 |
| --- | --- |
| 리전 | 서울 ap-northeast-2 |
| OS / 아키텍처 | Ubuntu 24.04 LTS / x86_64 |
| 인스턴스 | t3.large, 2 vCPU / 8GiB |
| 디스크 | gp3 50GiB, 암호화 활성화 |
| 운영 | 개발·시연할 때 실행, 사용 후 EC2 중지 |

로컬 컨테이너 메모리 사용량 약 3.6GiB를 바탕으로 시작한 사양이며, 부하 시 적정 용량은 별도 측정한다. 월 6만 원 예산에 맞춰 비용 알림을 설정하고 실제 사용 비용을 확인한다. 알림 자체가 서버를 자동 중지하지는 않는다. T3 크레딧 모드도 확인한다. Standard는 크레딧 소진 시 성능이 제한될 수 있고 Unlimited는 추가 요금이 발생할 수 있다.

인바운드는 아래 규칙만 필요한 사람에게 허용한다.

| 포트 | 용도 | 소스 |
| --- | --- | --- |
| 22 | SSH 관리 | 관리자 공인 IPv4/32 |
| 3000 | 대시보드 | 시연 참여자 공인 IPv4/32 |
| 80 | WAF → JuiceShop | 테스트 참여자 공인 IPv4/32 |

`192.168.x.x`, 핫스팟의 `172.20.10.x` 같은 사설 IP를 입력하지 않는다. 팀원은 실제 접속할 PC에서 공인 IPv4를 확인한다. Wi-Fi·VPN·핫스팟 변경 시 다시 확인한다. DB·Kafka·AI·백엔드 포트를 외부에 추가 개방하지 않는다.

아래 `<EC2_PUBLIC_IP>`, `<KEY_PATH>`, `<DEPLOY_BRANCH>`는 실제 값으로 교체한다. 개인 키·비밀번호·JWT를 Git이나 문서에 기록하지 않는다.

**로컬 Windows PowerShell:**

```powershell
ssh -i "<KEY_PATH>" ubuntu@<EC2_PUBLIC_IP>
```

**EC2 Ubuntu 터미널:**

```bash
uname -m
free -h
df -h /
```

Docker가 없다면 [Ubuntu 공식 설치 절차](https://docs.docker.com/engine/install/ubuntu/)의 apt 저장소 방식으로 Docker Engine, CLI, containerd, Buildx, Compose 플러그인을 설치한다. EC2에는 호스트용 Java·Node·Python 개발 환경이 필요하지 않다.

```bash
sudo systemctl enable --now docker
sudo systemctl is-active docker
sudo docker run --rm hello-world
sudo docker compose version
```

`docker.service does not exist`이면 설치가 완료됐는지 먼저 확인한다. 이후 Docker 명령은 `sudo`를 붙이는 기준이다.

## 3. 코드와 모델 전달

AWS 준비 PR이 develop에 머지됐다면 `<DEPLOY_BRANCH>`에 `develop`을 사용한다. 삭제된 작업 브랜치를 지정하지 않는다. 비공개 저장소는 별도 GitHub 인증이 필요하며 토큰을 URL에 넣지 않는다.

**EC2:**

```bash
cd ~
git clone --branch <DEPLOY_BRANCH> --single-branch https://github.com/Nagyun-oh/2026_kw_capstone_project.git
cd ~/2026_kw_capstone_project
git branch --show-current
git log -1 --oneline
ls -l compose.aws.yaml aws.env.example docs/db/security-db-schema.sql
grep -n proxy_pass frontend/nginx.conf
```

중요: `/api/`와 `/ws-security`의 두 `proxy_pass`는 모두 다음 값이어야 한다.

```nginx
proxy_pass http://backend:8080;
```

EC2에서만 수정하고 Git에 반영하지 않으면 새 clone에서 오류가 재발한다. 문서 작성 시 로컬 파일에는 `security-backend:8080`이 남아 있어 **로컬 수정·커밋·push가 후속 작업**이다. 서비스 이름은 `backend`이며 이미지 이름과 혼동하지 않는다.

AI 서비스는 `AI_new/`(3모델 앙상블)로 빌드한다. 모델 `.pkl`은 Git에서 제외돼 있으며 AI 팀이 공개 Kaggle 데이터셋 [hyunwook23/capstone-new2026](https://www.kaggle.com/datasets/hyunwook23/capstone-new2026)에 올린다. 데이터셋 전체(약 1.3GB)가 아니라 서빙에 필요한 2개 파일만 **버전을 고정해** EC2에서 직접 받는다. 로컬 DB 폴더나 과거 WAF 로그를 서버에 복사하지 않는다.

받을 파일·Kaggle 버전·SHA-256은 [AI_new/models.lock.json](../AI_new/models.lock.json)에 고정돼 있다. CI·CD와 같은 스크립트를 사용한다.

| Kaggle 파일 | 저장 위치 |
| --- | --- |
| `model_bundle_tree_schema.pkl` | `AI_new/models/model_bundle_tree_schema.pkl` |
| `model_bundle.pkl` | `AI_new/models/transformer/model_bundle.pkl` |

**EC2:**

```bash
cd ~/2026_kw_capstone_project
python3 scripts/fetch_models.py
```

두 파일 모두 `OK`여야 한다. 해시가 다르면 스크립트가 파일을 저장하지 않고 실패한다. `.pkl`은 로드 시 임의 코드를 실행할 수 있으므로 이 경우 사용하지 말고 AI 팀에 확인한다. 트랜스포머 번들은 기동 시 Git에 포함된 `model_bundle.pkl.manifest.json`의 `bundle_sha256`과도 비교된다.

모델 교체 절차: AI 팀이 Kaggle에 새 버전을 올린 뒤 `models.lock.json`의 `version`과 각 `sha256`을 갱신하는 PR을 만든다. 트랜스포머를 바꾸면 매니페스트도 함께 갱신한다.

## 4. 환경변수와 WAF 로그 디렉터리

다음 복사는 `.env.aws`가 없을 때만 수행한다. 기존 비밀값을 덮어쓰지 않는다.

```bash
test -e .env.aws || (umask 077; cp aws.env.example .env.aws)
chmod 600 .env.aws
openssl rand -base64 32
nano .env.aws
```

| 변수 | 설정 |
| --- | --- |
| MYSQL_ROOT_PASSWORD | 새 root 비밀번호 |
| DB_USERNAME | security_app |
| DB_PASSWORD | root와 다른 앱 계정 비밀번호 |
| JWT_SECRET | 생성한 Base64 키를 저장하고 지속 사용 |
| JWT_EXPIRATION_MS | 86400000 |
| CORS_ALLOWED_ORIGINS | http://현재_EC2_공인_IP:3000 |

Nano 저장: Ctrl+O → Enter, 종료: Ctrl+X. 실제 파일은 Git 제외 여부를 확인한다.

```bash
git check-ignore .env.aws
git ls-files -- .env.aws
sudo docker compose --env-file .env.aws -f compose.aws.yaml config --quiet
echo $?
```

첫 명령은 `.env.aws`, 두 번째는 빈 출력, 구성 검증은 종료 코드 0이 기준이다. 값이 출력되는 전체 `config` 결과는 공유하지 않는다. DB 초기화 후 환경변수 파일의 비밀번호만 변경해도 DB 계정 비밀번호가 바뀌는 것은 아니다.

WAF는 호스트의 `waf/logs`를 바인드 마운트한다. 최초 실행 전 이미지의 실행 UID/GID를 확인한다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml pull waf
sudo docker compose --env-file .env.aws -f compose.aws.yaml run --rm --no-deps --entrypoint id waf
sudo ls -ldn waf/logs
sudo ls -lan waf/logs
```

이번 배포는 `101:101(nginx)`이었다. 이미지가 달라지면 재확인한다. 새 디렉터리가 없으면 `mkdir -p waf/logs`로 생성한다. **빈 디렉터리 또는 `.gitkeep`만 있는 최초 배포**에서 확인한 UID/GID로 적용한다.

```bash
sudo chown 101:101 /home/ubuntu/2026_kw_capstone_project/waf/logs
sudo chmod 755 /home/ubuntu/2026_kw_capstone_project/waf/logs
```

이미 로그 파일이 있으면 디렉터리 변경만으로 파일 권한까지 바뀌지 않는다. 해당 파일의 소유권을 별도로 확인한다. 프로젝트 전체의 소유권이나 권한을 변경하지 않는다.

## 5. 이미지 빌드와 신규 DB 초기화

메모리 부담을 줄이기 위해 순서대로 빌드한다. 오류가 발생하면 해당 단계에서 해결 후 진행한다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml build backend
sudo docker compose --env-file .env.aws -f compose.aws.yaml build frontend
sudo docker compose --env-file .env.aws -f compose.aws.yaml build ai
sudo docker compose --env-file .env.aws -f compose.aws.yaml up -d db
sudo docker compose --env-file .env.aws -f compose.aws.yaml ps db
sudo docker compose --env-file .env.aws -f compose.aws.yaml logs --tail=100 db
```

MySQL은 새 데이터 볼륨의 최초 초기화에서만 마운트된 SQL을 실행한다. 기존 볼륨이 있으면 SQL을 바꿔도 자동 재적용되지 않는다. `healthy` 확인 후 DB_PASSWORD를 입력해 접속한다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml exec db mysql -u security_app -p security_db
```

```sql
SHOW TABLES;
SELECT 'admin_users' AS table_name, COUNT(*) AS row_count FROM admin_users
UNION ALL SELECT 'network_logs', COUNT(*) FROM network_logs
UNION ALL SELECT 'detected_threats', COUNT(*) FROM detected_threats
UNION ALL SELECT 'ip_blacklist', COUNT(*) FROM ip_blacklist;
exit;
```

이번 초기화에서는 핵심 4개 테이블과 SPRING_SESSION 관련 2개 테이블을 확인했다. 핵심 테이블 건수는 각각 0이었다. JPA `validate`를 유지하며 테이블 누락을 `create` 설정으로 해결하지 않는다.

## 6. 전체 실행과 통합 검증

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml up -d
sudo docker compose --env-file .env.aws -f compose.aws.yaml ps -a
curl -fsS http://127.0.0.1:8080/actuator/health
curl -fsS http://127.0.0.1:8000/health
curl -I http://127.0.0.1/
```

기동 대기 후 백엔드 UP, AI model_loaded=true, WAF 응답 및 health, 전체 서비스의 재시작 여부를 확인한다. AI의 `/actuator/health`는 올바른 경로가 아니다. `Up`만으로 애플리케이션 준비 완료를 판단하지 않는다.

브라우저 접속 주소:

- 대시보드: `http://<EC2_PUBLIC_IP>:3000`
- WAF → JuiceShop: `http://<EC2_PUBLIC_IP>`

1. JuiceShop에서 식별 가능한 요청을 발생시킨다. 예: `/?deployment_check=20260926`.
2. 대시보드에서 요청 URL·시각·로그 ID를 확인한다.
3. backend·ai 로그에서 동일 logId의 분석 요청과 결과 수신을 확인한다.
4. 모델이 위협으로 판정한 결과는 탐지 목록과 연결된 원본 로그를 비교한다. 모든 정상 요청이 위협으로 저장되어야 하는 것은 아니다.
5. 새로고침 후에도 데이터가 유지되는지 확인하고, 새로고침 없이 갱신되는지 및 브라우저 WebSocket 연결은 별도로 확인한다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml logs --since=5m --tail=150 fluent-bit backend ai
sudo docker stats --no-stream
```

health 응답이나 화면 한 장만으로 전체 파이프라인·모델 정확도를 검증했다고 기록하지 않는다.

## 7. EC2 중지·재시작 및 데이터 보존

먼저 MySQL에서 건수와 최근 ID를 기록한다.

```sql
SELECT 'network_logs' AS table_name, COUNT(*) AS row_count FROM network_logs
UNION ALL SELECT 'detected_threats', COUNT(*) FROM detected_threats
UNION ALL SELECT 'ip_blacklist', COUNT(*) FROM ip_blacklist;
SELECT id, request_url, created_at FROM network_logs ORDER BY id DESC LIMIT 5;
```

팀원의 테스트를 중단하고 EC2에서 실행한다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml stop
```

AWS 콘솔 → 인스턴스 선택 → 인스턴스 상태 → **중지**. `종료`는 삭제이므로 선택하지 않는다. 중지 상태에서도 EBS 비용은 유지된다.

다시 시작한 뒤 현재 퍼블릭 IP를 확인하고 SSH에 재접속한다. IP가 변경되면 `.env.aws`의 CORS 주소와 팀원에게 전달하는 URL도 갱신한다. 보안 그룹 소스는 서버 IP가 아니라 접속자의 공인 IP다.

```bash
cd ~/2026_kw_capstone_project
nano .env.aws
sudo docker compose --env-file .env.aws -f compose.aws.yaml config --quiet
sudo docker compose --env-file .env.aws -f compose.aws.yaml up -d
sudo docker compose --env-file .env.aws -f compose.aws.yaml ps -a
```

6절 health/API 검증을 반복하고 기존 ID가 남아 있는지 비교한다. 대기 메시지·새 요청으로 건수는 증가할 수 있다. `/?restart_check=after_ec2_restart` 요청으로 신규 처리도 확인한다.

이는 명시적으로 `stop`한 서비스를 수동 재기동한 검증이다. 부팅 시 자동 시작, 백업 복구, 디스크 장애 복구는 별개다. 데이터 삭제용으로 `down -v`나 `docker volume prune`을 사용하지 않는다. 프로젝트 이름을 바꾸면 다른 볼륨이 연결될 수 있으므로 기존 `security-platform-aws` 이름을 유지한다.

## 8. 변경 배포와 문제 해결

### 코드 변경 반영

GitHub Actions CD를 설정했다면 [CI/CD 문서 8장](07_cicd_pipeline.md#8-첫-배포와-롤백)의 **Deploy to EC2** 실행이 기본 배포 방법이다. CD로 배포한 뒤에는 저장소가 배포 커밋에 고정(detached HEAD)되므로 아래 수동 절차 전에 `git switch develop`을 먼저 실행한다.

EC2 수정이 남아 있으면 먼저 `git diff`로 확인하고 로컬/Git에 반영한다. 변경을 강제로 덮어쓰지 않는다. 정상 배포는 Git으로 변경을 가져온 뒤 해당 서비스만 재빌드한다.

```bash
git status --short
git diff
git pull --ff-only
# 아래 명령은 수정한 서비스에 대해서만 실행
sudo docker compose --env-file .env.aws -f compose.aws.yaml up -d --build --no-deps frontend
```

backend 또는 ai 수정도 같은 방식이다. 모델 버전이 바뀌면 `python3 scripts/fetch_models.py` 실행 후 `ai`를 재빌드한다. 환경변수 변경은 `restart`만으로 반영되지 않으므로 `up -d`로 적용한다.

### WAF Permission denied

- 증거: `/var/log/nginx/access.log`, `error.log` 접근 거부, ExitCode=1, OOMKilled=false.
- 원인: 실행 계정 101:101과 로그 디렉터리 소유자 1000:1000 불일치. 775 권한에서 WAF는 쓰기 불가.
- 해결: WAF 중지 → 4절의 로그 디렉터리 소유권·권한 수정 → `up -d waf`.
- 확인: 실행 상태 유지, 이후 health 확인 및 HTTP 200. 호스트 권한 수정이므로 이미지 재빌드 불필요.

### 프론트엔드 host not found

`host not found in upstream "security-backend"`는 서비스 이름 불일치였다. 두 프록시를 `backend:8080`으로 수정하고 프론트엔드를 재빌드·교체했다. 서버에서만 고치지 말고 저장소에도 반영한다.

### 백엔드는 UP인데 대시보드가 502

```bash
curl -i --max-time 10 "http://127.0.0.1:8080/api/v1/logs?page=0&size=1"
curl -i --max-time 10 "http://127.0.0.1:3000/api/v1/logs?page=0&size=1"
sudo docker compose --env-file .env.aws -f compose.aws.yaml logs --since=5m --tail=80 frontend
```

실제 사례에서 직접 호출은 200, Nginx 경유는 502였다. 백엔드 재생성 후 Nginx가 이전 IP를 사용하는 가능성을 점검하고 프론트엔드 재시작을 안내했으며, 이후 사용자가 화면 조회를 확인했다. 당시 upstream 오류 로그와 IP 비교는 확보하지 않아 DNS 캐시를 확정 원인으로 기록하지 않는다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml restart frontend
```

그 후 동일 API를 재검증한다. 반복 발생하면 DNS 재해석 및 기동 순서 개선을 별도 작업으로 진행한다.

### SSH·외부 접근

- `Identity file ... not accessible`: 실행하는 PC/WSL 기준 키 경로와 파일명 확인.
- `Permission denied (publickey)`: 계정명 및 개인 키와 등록된 공개 키의 일치 확인.
- Windows `UNPROTECTED PRIVATE KEY FILE`: 개인 키의 상속·일반 사용자 접근 권한을 정리.
- 외부 접속 실패: 서버의 현재 공인 IP, HTTP 사용, 해당 포트의 접속자 공인 IPv4/32, 보안 그룹 연결 확인.
- 웹 화면만 보는 팀원에게 SSH 키나 22 포트 허용은 필요하지 않다.

## 9. 후속 작업

- [ ] EC2에서 고친 Nginx 주소를 로컬·Git에도 반영하고 재현 확인.
- [ ] Fluent Bit 읽기 위치·버퍼 영속화 및 로그 보관·중복 처리 정책 확정.
- [ ] DB 백업·복구 검증. EC2 중지·시작 성공은 백업이 아님.
- [ ] 이미지 태그/digest 고정과 부하·비용 측정.
- [ ] 관리자 인증·권한 및 HTTPS 적용 후 공개 범위 재검토.
- [ ] 필요한 경우 테스트 데이터 초기화 스크립트 추가. 현재는 미구현.
- [ ] CI/CD 및 자동 기동 검증. 진행 상황은 [CI/CD 문서](07_cicd_pipeline.md) 참고.

DB의 `DELETE`는 AUTO_INCREMENT를 초기화하지 않는다. 화면 건수와 고유 ID는 다르며, 삭제 후 ID가 이어지는 것은 정상이다. Kafka 메시지가 logId를 참조하므로 표시 번호를 위해 기존 ID를 재사용하지 않는다.

## 참고

- [Docker Ubuntu 설치](https://docs.docker.com/engine/install/ubuntu/)
- [Docker Compose 환경변수](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/)
- [MySQL 컨테이너 초기화](https://hub.docker.com/_/mysql)
- [EC2 중지·시작](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html)
- [로컬 실행 문서](05_infra_deployment.md)
