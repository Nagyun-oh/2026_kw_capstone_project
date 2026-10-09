# AWS EC2 배포 및 운영 절차

## 1. 범위와 검증 기록

단일 EC2에서 [compose.aws.yaml](../compose.aws.yaml)로 9개 서비스를 실행하는 개발·시연 환경이다. 로컬 전용 [compose.yaml](../compose.yaml)과 혼합해서 실행하지 않는다.

현재 접속 구성은 **DuckDNS 도메인 + EC2 호스트 Nginx의 HTTPS + 프론트 컨테이너**다. 앱 이미지 배포는 GitHub Actions의 **Deploy to EC2**를 수동 실행하는 방식이다. PR 머지만으로 배포되지는 않는다.

### 1-1. 이전 배포 검증 기록 (2026-09-26)

아래는 당시 사용자가 제공한 CLI 출력과 동작 확인에 근거한 기록이다. 현재 인증·화면 변경을 AWS에서 검증한 결과와 구분한다. 문서 수정 과정에서 EC2 작업을 다시 실행한 것은 아니다.

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

당시 배포 버전은 관리 API 접근을 보안 그룹으로 제한했다. 새 버전은 HTTP 세션·CSRF·관리자 권한 검사를 적용하며, AWS 통합 검증은 새 이미지 배포 후 수행한다. WAF는 `DetectionOnly`이며 블랙리스트 표시가 실제 WAF 차단을 의미하지 않는다.

### 1-2. HTTPS 전환 진행 상태 (2026-10-08 기준)

| 항목 | 확인 결과 |
| --- | --- |
| 도메인 | `security-monitor-kw.duckdns.org`로 EC2 접속 확인 |
| WAF 포트 이동 | `8081:8080`, 컨테이너 healthy 및 HTTP 200 확인 |
| 호스트 Nginx | active/running, HTTPS 확인 페이지 및 기존 프론트 화면 접속 확인 |
| 인증서 | 발급 성공, `certbot renew --dry-run` 성공, 자동 갱신 타이머 확인 |
| 내부 프론트 포트 | EC2의 `127.0.0.1:3000:80` 바인딩 적용 후 HTTPS 경유 접속 확인 |
| 새 프론트 프록시 설정 | 로컬 이미지의 `nginx -t` 성공 |
| 새 세션 인증·대시보드 이미지 | AWS 배포 및 쿠키·API·WebSocket 통합 검증 예정 |

마지막으로 확인한 AWS 앱 이미지 태그는 `6fc6a36675f3efa59c01587a94b2939cc6240a48`이다. HTTPS 접속 성공이 새 앱 이미지 배포 완료를 의미하지는 않는다. 프론트 자동 테스트는 이번 변경에서 제외했으며 빌드와 사용자 수동 검증을 구분해 기록한다.

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
| 80 | 인증서 HTTP-01 검증 및 HTTPS 리다이렉트 | 0.0.0.0/0 |
| 443 | HTTPS 대시보드 | 접속을 허용할 사용자 공인 IPv4/32 |

WAF의 8081번은 `127.0.0.1:8081:8080`으로 바인딩하므로 보안 그룹에서 8081 인바운드 규칙을 두지 않는다(기존 규칙은 삭제). 프론트의 3000번은 `127.0.0.1:3000:80`으로 바인딩한다. 외부 브라우저는 443번에 접속하고, 호스트 Nginx가 EC2 내부에서 3000번으로 전달한다. HTTPS 화면 접속 확인 후 기존 3000번 인바운드 규칙을 제거한다. 80번 전체 허용은 **WAF를 8081번으로 이동한 뒤** 적용한다.

`192.168.x.x`, 핫스팟의 `172.20.10.x` 같은 사설 IP를 입력하지 않는다. 팀원은 실제 접속할 PC에서 공인 IPv4를 확인한다. Wi-Fi·VPN·핫스팟 변경 시 다시 확인한다. DB·Kafka·AI·백엔드 포트를 외부에 추가 개방하지 않는다.

아래 `<EC2_PUBLIC_IP>`, `<KEY_PATH>`, `<DEPLOY_BRANCH>`는 실제 값으로 교체한다. 개인 키·비밀번호를 Git이나 문서에 기록하지 않는다.

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

### 2-1. 도메인과 접속 구조

```text
브라우저 → https://security-monitor-kw.duckdns.org:443
             → EC2 호스트 Nginx (TLS 종료)
               → http://127.0.0.1:3000
                 → 프론트 컨테이너 Nginx
                   ├─ /            → React 화면
                   ├─ /api/        → backend:8080
                   └─ /ws-security → backend:8080

테스트 요청 → https://<JuiceShop용 호스트명> (호스트 Nginx, TLS 종료)
             → http://127.0.0.1:8081
               → WAF → JuiceShop
```

WAF는 Docker 게이트웨이(`WAF_TRUSTED_PROXY`)를 거친 호스트 Nginx의 `X-Forwarded-For`를 실제 클라이언트 IP로 복원하여 로그의 `remote_addr`에 기록한다. 8081번을 외부에 열면 헤더 위조가 가능하므로 loopback 바인딩을 유지한다.

DuckDNS의 `current ip`에는 **EC2의 현재 공인 IPv4**를 등록한다. 보안 그룹 소스에는 **접속자의 공인 IPv4**를 넣는다. DuckDNS 토큰은 공유하거나 Git에 저장하지 않는다. EC2 주소가 변경되면 DNS 레코드를 갱신해야 하며, 자동 갱신은 별도 구성이다.

로컬 PowerShell에서 DNS를 확인한다.

```powershell
Resolve-DnsName -Name "security-monitor-kw.duckdns.org" -Type A
```

#### JuiceShop용 호스트 Nginx 설정과 WAF_TRUSTED_PROXY

`.env.aws`에 게이트웨이 주소를 설정한다(`aws.env.example` 참고).

```bash
docker network inspect security-platform-aws_default -f '{{(index .IPAM.Config 0).Gateway}}'
# 출력값을 .env.aws의 WAF_TRUSTED_PROXY=<값> 으로 기록
```

호스트 Nginx의 JuiceShop 서버 블록에서 클라이언트가 보낸 `X-Forwarded-For`를 덮어쓴다.

```nginx
location / {
    proxy_pass http://127.0.0.1:8081;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

`sudo nginx -t && sudo systemctl reload nginx` 후 WAF 컨테이너를 재생성한다. 검증: 브라우저 접속 시 로그에 본인 공인 IP가 남고, `curl -H "X-Forwarded-For: 1.2.3.4" ...`를 보내도 `1.2.3.4`가 기록되지 않으며, `curl http://<EC2 IP>:8081/`은 실패해야 한다. 기존 DB 기록은 변경되지 않는다.

### 2-2. 호스트 Nginx와 인증서 최초 설정

기존 서버는 먼저 `compose.aws.yaml`의 WAF 포트를 `8081:8080`으로 변경·재생성하여 80번을 확보한다. 이미 HTTPS 설정을 마친 서버에서는 아래 초기 확인 페이지로 덮어쓰지 않는다.

**EC2:**

```bash
sudo apt update
sudo apt install -y nginx snapd
sudo systemctl enable --now nginx
sudo systemctl status nginx --no-pager
sudo nano /etc/nginx/sites-available/security-dashboard
```

최초 인증서 발급 전 설정:

```nginx
server {
    listen 80;
    server_name security-monitor-kw.duckdns.org;

    location / {
        default_type text/plain;
        return 200 "Security Monitor HTTPS setup ready\n";
    }
}
```

심볼릭 링크는 최초 한 번만 만든다. 대상은 `sites-available`이 아니라 `sites-enabled`다.

```bash
sudo ln -s /etc/nginx/sites-available/security-dashboard /etc/nginx/sites-enabled/security-dashboard
sudo nginx -t
```

검사 성공 후 적용하고 HTTP 주소에서 확인 문구가 나오는지 확인한다.

```bash
sudo systemctl reload nginx
sudo snap install --classic certbot
sudo /snap/bin/certbot --nginx -d security-monitor-kw.duckdns.org --redirect
sudo /snap/bin/certbot certificates
sudo /snap/bin/certbot renew --dry-run
systemctl list-timers --all | grep -i certbot
```

이메일·약관은 실행자가 직접 입력·확인한다. HTTP-01 검증에는 외부에서 접근 가능한 80번이 필요하다. Certbot은 인증서 설정과 HTTP→HTTPS 리다이렉트를 구성한다. `renew --dry-run`은 갱신 모의 검사이며 타이머 조회는 자동 실행 예약 확인이다. 서버가 꺼져 있는 동안에는 갱신이 실행되지 않는다. [Certbot 안내](https://certbot.eff.org/instructions?ws=nginx&os=snap), [HTTP-01 검증](https://letsencrypt.org/docs/challenge-types/)

### 2-3. HTTPS 입구와 프론트 연결

3~6절의 앱 준비 후 `curl -I http://127.0.0.1:3000/`으로 프론트 응답을 확인한다. 외부 3000번 접근은 필요하지 않다.

호스트의 `/etc/nginx/conf.d/security-websocket.conf`에 다음을 저장한다.

```nginx
map $http_upgrade $dashboard_connection_upgrade {
    default upgrade;
    ''      close;
}
```

호스트의 `/etc/nginx/sites-available/security-dashboard`에서 **443번을 수신하는 server 블록의 `location /`만** 아래로 교체한다. Certbot의 인증서 경로·SSL 설정과 80번 리다이렉트 블록은 유지한다.

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;

    # 외부에서 임의로 전달한 헤더 대신 호스트 Nginx의 연결 정보 사용
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_set_header Forwarded "";
    proxy_set_header X-Forwarded-Prefix "";

    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $dashboard_connection_upgrade;
    proxy_buffering off;
    proxy_read_timeout 3600s;
}
```

`sudo nginx -t` 성공 후 `sudo systemctl reload nginx`로 적용한다. 브라우저에서 인증서 경고 없이 프론트 화면이 나오는지 확인한다.

호스트 Nginx 파일과 `/etc/letsencrypt`는 앱 컨테이너 및 Git 배포 대상 밖에 있다. 앱 배포가 이 설정을 자동 생성하지 않는다. 서버 재구축 시 이 절차로 구성하며 인증서 개인 키를 저장소에 복사하지 않는다.

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

현재 저장소는 서비스 이름 `backend`를 사용한다. EC2에서만 고치지 말고 변경을 PR에 포함한다. 이미지 이름과 서비스 이름을 혼동하지 않는다.

[frontend/nginx.conf](../frontend/nginx.conf)는 로컬·AWS 이미지에 공통으로 포함된다. 두 경로 모두 `X-Forwarded-Proto`를 `$original_scheme`으로 전달하여 앞단의 HTTPS 정보를 보존한다. 전달 헤더가 없는 로컬 HTTP 환경은 `$scheme`을 사용한다. AWS에서는 2-3절의 호스트 헤더 설정 및 3000번 내부 바인딩과 함께 적용한다.

**현재 기본 배포는 ECR 이미지를 사용하는 CD다.** CI/CD에서 모델 다운로드·검증 후 AI 이미지에 포함하므로 EC2에서 모델을 별도로 받을 필요가 없다. 아래 모델 전달 절차는 **EC2 수동 빌드 시에만** 사용한다.

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
nano .env.aws
```

| 변수 | 설정 |
| --- | --- |
| MYSQL_ROOT_PASSWORD | 최초 DB 생성 시 사용할 root 비밀번호. 기존 DB는 기존 값 유지 |
| DB_USERNAME | security_app |
| DB_PASSWORD | root와 다른 앱 계정 비밀번호 |
| CORS_ALLOWED_ORIGINS | `https://security-monitor-kw.duckdns.org` (끝에 `/` 없음) |
| APP_BOOTSTRAP_ADMIN_ENABLED | 기본 `false`, 최초 관리자 발급 시에만 `true` |
| APP_BOOTSTRAP_ADMIN_USERNAME | 최초 발급할 관리자 ID. 발급하지 않을 때는 비움 |
| APP_BOOTSTRAP_ADMIN_PASSWORD | 최초 발급할 관리자 비밀번호. 발급 완료 후 제거 |

CD가 사용하는 `IMAGE_REGISTRY_PREFIX`와 `IMAGE_TAG`가 이미 있으면 유지한다. JWT 키는 새 인증 구성에서 사용하지 않는다. 환경변수 파일에 비밀번호를 넣을 때는 따옴표로 감싸 Compose의 값 해석을 확인하고, 실제 값을 명령 인자·로그·Git에 남기지 않는다.

AWS Compose의 `backend.environment`에는 다음 설정이 적용된다.

```yaml
SESSION_COOKIE_SECURE: "true"
SERVER_FORWARD_HEADERS_STRATEGY: native
```

쿠키는 `JSESSIONID`, `Path=/`, `HttpOnly`, `SameSite=Lax`이며 AWS에서는 `Secure`를 사용한다. 백엔드는 Tomcat의 전달 헤더 처리를 통해 원래 HTTPS 요청을 인식한다. 이는 앞단의 헤더 덮어쓰기 및 직접 접근 제한과 함께 사용한다. [Spring Boot 프록시 설정](https://docs.spring.io/spring-boot/3.5/how-to/webserver.html)

로컬 Compose의 `SESSION_COOKIE_SECURE: "false"`는 유지한다. 프론트는 `API_BASE_URL=''`, `WS_URL='/ws-security'`의 상대 경로를 사용하며 운영 빌드에 `localhost:8080` 또는 `ws://EC2_IP:8080`을 주입하지 않는다.

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

### 4-1. 운영 최초 관리자 발급

이 절차는 `ProdAdminInitializer`가 포함된 **새 백엔드 이미지**에서 사용한다. 실행 중인 DB에 접속해 기존 계정을 먼저 확인한다. `-p`에는 DB_PASSWORD를 대화형으로 입력한다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml exec db mysql -u security_app -p security_db
```

```sql
SELECT id, username, role FROM admin_users;
exit;
```

기존 `ROLE_ADMIN` 계정이 있으면 이를 사용하고 생성 옵션은 `false`로 유지한다. 초기화 코드는 기존 관리자 비밀번호를 재설정하지 않는다. 계정이 없는 경우에만 EC2의 `.env.aws`에 아래 항목을 설정한 뒤 새 이미지를 배포한다.

```ini
APP_BOOTSTRAP_ADMIN_ENABLED=true
APP_BOOTSTRAP_ADMIN_USERNAME=REPLACE_WITH_ADMIN_USERNAME
APP_BOOTSTRAP_ADMIN_PASSWORD='REPLACE_WITH_ADMIN_PASSWORD'
```

아이디는 앞뒤 공백 제거 후 1~50자, 비밀번호는 현재 구현상 8자 이상·UTF-8 기준 72바이트 이하로 검증한다. 운영에는 충분히 긴 고유 비밀번호를 사용한다. 같은 아이디의 기존 계정을 임의로 승격하지 않으며, 비밀번호는 BCrypt로 저장한다. 단일 백엔드 인스턴스의 최초 발급을 전제로 한다.

배포 후 백엔드 로그의 생성 완료 또는 기존 관리자 생략 메시지와 실제 HTTPS 로그인을 확인한다. 완료하면 `.env.aws`를 다시 편집해 생성 옵션을 `false`로 바꾸고 아이디·비밀번호 값을 비운다. 환경변수 제거까지 반영하려면 새 이미지 배포가 끝난 상태에서 다음을 실행한다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml up -d --no-build --no-deps --force-recreate backend
sudo docker compose --env-file .env.aws -f compose.aws.yaml restart frontend
```

백엔드 컨테이너가 재생성되면 메모리의 로그인 세션은 종료될 수 있다. health 확인 후 다시 로그인한다. DB의 관리자 계정은 유지된다.

## 5. 이미지 빌드와 신규 DB 초기화

**기본 경로는 8절의 ECR/CD 배포다.** 기존 DB가 있는 서버에서는 볼륨을 다시 만들거나 초기화 SQL을 재실행하지 않는다. 아래 빌드는 CD를 사용하지 않는 최초 설치·수동 복구용이다. `.env.aws`에 ECR용 `IMAGE_*` 값이 있으면 해당 태그로 로컬 빌드하지 말고 8절의 수동 복구 조건부터 확인한다.

수동 빌드는 메모리 부담을 줄이기 위해 순서대로 실행한다. 이미지 빌드 성공은 테스트 통과를 의미하지 않는다.

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

2026-09-26 초기화에서는 핵심 4개 테이블과 SPRING_SESSION 관련 2개 테이블을 확인했다. 핵심 테이블 건수는 각각 0이었다. 세션 테이블의 존재만으로 현재 인증 세션이 DB에 영속화된다고 판단하지 않는다. 현재 인증 구성은 HTTP 세션을 사용하며 서버 재시작 후 로그인 유지는 별도 보장하지 않는다. JPA `validate`를 유지하며 테이블 누락을 `create` 설정으로 해결하지 않는다.

## 6. 전체 실행과 통합 검증

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml up -d
sudo docker compose --env-file .env.aws -f compose.aws.yaml ps -a
curl -fsS http://127.0.0.1:8080/actuator/health
curl -fsS http://127.0.0.1:8000/health
curl -I http://127.0.0.1:8081/
curl -I http://127.0.0.1:3000/
```

기동 대기 후 백엔드 UP, AI model_loaded=true, WAF 응답 및 health, 전체 서비스의 재시작 여부를 확인한다. AI의 `/actuator/health`는 올바른 경로가 아니다. `Up`만으로 애플리케이션 준비 완료를 판단하지 않는다.

브라우저 접속 주소:

- 대시보드: `https://security-monitor-kw.duckdns.org`
- WAF → JuiceShop: 호스트 Nginx에 구성한 JuiceShop용 HTTPS 주소(8081 직접 접속 불가)

새 인증 이미지 배포 후 브라우저 개발자 도구에서 다음을 검증한다. 쿠키 값·CSRF 토큰·비밀번호를 캡처나 문서에 포함하지 않는다.

| 검증 항목 | 완료 기준 |
| --- | --- |
| HTTPS | 인증서 경고 없이 화면 표시, 혼합 콘텐츠 오류 없음 |
| CSRF·로그인 | `/api/v1/auth/csrf` 조회 후 올바른 관리자 계정으로 로그인 성공 |
| 쿠키 | `JSESSIONID`의 Secure·HttpOnly·SameSite=Lax·Path=/ 확인 |
| 세션 유지 | 새로고침 후 `/api/v1/auth/me` 정상 응답 |
| 접근 보호 | 비로그인 보호 GET API는 401, 유효한 CSRF 없이 변경 요청 시 403 |
| WebSocket | 연결됨 표시, WebSocket 전송 사용 시 `wss://` 및 STOMP 구독 성공 |
| 로그아웃·만료 | 보호 API 조회 거부 및 기존 연결 종료. 다중 탭·유휴 세션도 확인 |

그다음 파이프라인을 확인한다.

1. JuiceShop에서 식별 가능한 요청을 발생시킨다. 예: `/?deployment_check=after_https_deploy`.
2. 대시보드에서 요청 URL·시각·로그 ID를 확인한다.
3. backend·ai 로그에서 동일 logId의 분석 요청과 결과 수신을 확인한다.
4. 모델이 위협으로 판정한 결과는 탐지 목록과 연결된 원본 로그를 비교한다. 모든 정상 요청이 위협으로 저장되어야 하는 것은 아니다.
5. 새로고침 후에도 데이터가 유지되는지 확인하고, 새로고침 없이 갱신되는지 및 브라우저 WebSocket 연결은 별도로 확인한다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml logs --since=5m --tail=150 fluent-bit backend ai
sudo docker stats --no-stream
```

health 응답이나 화면 한 장만으로 전체 파이프라인·모델 정확도를 검증했다고 기록하지 않는다.

새로 생성하는 로그·탐지 등의 시각은 UTC 기준으로 기록하고, API 응답에는 오프셋을 포함하며 화면은 `Asia/Seoul`로 표시한다. 기존 데이터의 시간대 보정은 이번 변경에 포함하지 않는다. `createdAt` 등 저장 시각과 원본 로그의 요청 발생 시각을 구분해 검증한다.

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

다시 시작한 뒤 현재 퍼블릭 IP와 DuckDNS 레코드가 일치하는지 확인하고 SSH에 재접속한다. 서버 IP가 변경되면 DNS 레코드를 갱신한다. **도메인이 같으면 CORS와 대시보드 URL은 유지**한다. 탄력적 IP를 사용하더라도 연결 상태를 확인한다. 보안 그룹 소스는 서버 IP가 아니라 접속자의 공인 IP다.

```bash
cd ~/2026_kw_capstone_project
sudo docker compose --env-file .env.aws -f compose.aws.yaml config --quiet
sudo docker compose --env-file .env.aws -f compose.aws.yaml up -d
sudo docker compose --env-file .env.aws -f compose.aws.yaml ps -a
sudo systemctl is-active nginx
sudo /snap/bin/certbot certificates
systemctl list-timers --all | grep -i certbot
```

6절 health/API 검증을 반복하고 기존 ID가 남아 있는지 비교한다. 로그인 세션이 종료됐다면 다시 로그인한다. 대기 메시지·새 요청으로 건수는 증가할 수 있다. `/?restart_check=after_ec2_restart` 요청으로 신규 처리도 확인한다. 장기간 중지했다면 인증서 유효기간과 갱신 상태도 확인한다.

이는 명시적으로 `stop`한 서비스를 수동 재기동한 검증이다. 부팅 시 자동 시작, 백업 복구, 디스크 장애 복구는 별개다. 데이터 삭제용으로 `down -v`나 `docker volume prune`을 사용하지 않는다. 프로젝트 이름을 바꾸면 다른 볼륨이 연결될 수 있으므로 기존 `security-platform-aws` 이름을 유지한다.

## 8. 변경 배포와 문제 해결

### 코드 변경 반영

현재 [.github/workflows/deploy.yml](../.github/workflows/deploy.yml)은 `workflow_dispatch`만 사용한다. 기본 흐름은 **PR → CI·리뷰 → develop 머지 → Deploy to EC2 수동 실행 → AWS 검증**이다. 상세 사전 설정은 [CI/CD 문서](07_cicd_pipeline.md)를 참고한다.

1. PR CI의 백엔드 테스트·빌드, 프론트 빌드, AI 이미지 기동 및 Compose 검사를 확인한다. 프론트 자동 테스트는 현재 실행하지 않는다.
2. EC2의 `.env.aws`에 HTTPS CORS 주소를 반영하고, 4-1절에 따라 최초 관리자 발급 여부를 결정한다.
3. EC2 저장소의 변경을 확인한다. 워크플로는 추적 파일에 미커밋 변경이 있으면 덮어쓰지 않고 중단한다.

```bash
git status --short
git diff HEAD -- compose.aws.yaml
```

4. EC2에서 수동 변경한 WAF `8081:8080`과 프론트 `127.0.0.1:3000:80` 설정이 **머지된 배포 대상 커밋에도 포함됐는지 확인**한다. 동일한 변경임을 확인한 뒤 해당 파일만 stash로 보관한다. 다른 변경이 있으면 따로 검토한다.

```bash
git stash push -m "EC2 HTTPS Compose settings before deployment" -- compose.aws.yaml
git status --short
```

stash는 실행 중인 컨테이너를 바꾸지 않지만 디스크의 Compose 파일은 이전 상태로 돌아간다. **새 커밋 배포 전에는 이 이전 파일로 `compose up`을 실행하지 않는다.** 배포 후에도 포트 변경이 이미 포함되어 있으므로 stash를 바로 재적용하지 않는다. 강제 reset으로 변경을 버리지 않는다.

5. GitHub → Actions → **Deploy to EC2 → Run workflow**, 브랜치 `develop`, `sha`는 비워 실행한다. SHA를 입력하면 현재 워크플로는 빌드를 생략하므로 새 배포에 임의의 SHA를 넣지 않는다.
6. ECR push·SSM 배포 성공 후 EC2의 커밋과 이미지 태그, 6절의 HTTPS 인증·실시간 연결을 확인한다.

```bash
git log -1 --oneline
sudo docker compose --env-file .env.aws -f compose.aws.yaml images
sudo docker compose --env-file .env.aws -f compose.aws.yaml ps -a
```

CD는 새 이미지를 pull하고 컨테이너를 재생성하며 `.env.aws`의 `IMAGE_*` 값을 갱신한다. 이미지에 포함되는 `frontend/nginx.conf`는 호스트 파일 편집이나 컨테이너 `restart`만으로 교체되지 않는다. 환경변수 변경도 재생성이 필요하다. 호스트 Nginx 설정은 2절처럼 별도로 검사·reload한다.

### 수동 복구와 롤백

CD를 쓸 수 없어 EC2에서 빌드해야 한다면, 먼저 변경을 보존하고 사용할 커밋을 확정한다. `.env.aws`를 별도로 안전하게 보관한 뒤 ECR용 `IMAGE_REGISTRY_PREFIX`·`IMAGE_TAG`를 제거해 기본 `security-*:aws` 이름을 사용한다. 이후 3절 모델 준비와 5절 빌드를 수행한다. ECR SHA 태그 아래에 로컬 빌드 이미지를 덮어쓰는 방식과 혼합하지 않는다.

CD 롤백은 ECR에 존재하는 이전 성공 SHA로 실행할 수 있지만, **HTTPS 전환 전 커밋은 WAF 80번 바인딩 등 현재 호스트 Nginx와 충돌할 수 있다.** 이전 Compose·인증·환경변수 호환성을 확인한 뒤 수행한다. 앱 이미지 롤백이 DB 데이터나 호스트 Nginx 설정을 되돌리는 것은 아니다.

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

위 사례는 이전 인증 구성 기준이다. 새 버전에서는 쿠키 없는 보호 GET API 요청의 **401이 정상**일 수 있다. health는 직접 확인하고, 데이터 응답은 HTTPS 로그인 후 브라우저 Network에서 확인한다. 내부 HTTP URL에 Secure 세션 쿠키를 억지로 전달하지 않는다. 호스트의 `sudo tail -n 80 /var/log/nginx/error.log`도 함께 확인해 어느 프록시 구간에서 실패했는지 구분한다.

```bash
sudo docker compose --env-file .env.aws -f compose.aws.yaml restart frontend
```

그 후 동일 API를 재검증한다. 반복 발생하면 DNS 재해석 및 기동 순서 개선을 별도 작업으로 진행한다.

### SSH·외부 접근

- `Identity file ... not accessible`: 실행하는 PC/WSL 기준 키 경로와 파일명 확인.
- `Permission denied (publickey)`: 계정명 및 개인 키와 등록된 공개 키의 일치 확인.
- Windows `UNPROTECTED PRIVATE KEY FILE`: 개인 키의 상속·일반 사용자 접근 권한을 정리.
- 외부 접속 실패: DNS와 EC2 공인 IP 일치, 대시보드 HTTPS 443번 또는 JuiceShop HTTP 8081번 사용, 해당 포트의 접속자 공인 IPv4/32 및 보안 그룹 연결 확인.
- `NXDOMAIN`: `duckdns.org` 철자와 DNS 레코드를 확인한다.
- 인증서는 정상인데 로그인·실시간 연결 실패: 새 앱 이미지 적용 여부, CORS의 HTTPS 주소, 쿠키 속성, 두 Nginx의 전달 헤더·Upgrade 설정을 확인한다.
- 웹 화면만 보는 팀원에게 SSH 키나 22 포트 허용은 필요하지 않다.

## 9. 후속 작업

- [ ] 인증·대시보드·UTC 시각·HTTPS 설정 PR의 CI·리뷰 완료 및 새 이미지 배포.
- [ ] 운영 최초 관리자 발급 여부 확인, 생성 후 옵션·비밀값 제거 및 재로그인 검증.
- [ ] 새 이미지에서 Secure 쿠키·CSRF·권한·세션 만료·WebSocket·탐지 통합 검증.
- [ ] HTTPS 접속 확인 후 3000번 외부 인바운드 규칙 제거 확인.
- [ ] Fluent Bit 읽기 위치·버퍼 영속화 및 로그 보관·중복 처리 정책 확정.
- [ ] DB 백업·복구 검증. EC2 중지·시작 성공은 백업이 아님.
- [ ] 외부 의존 이미지 태그/digest 고정과 부하·비용 측정. 앱 이미지는 ECR SHA 태그로 추적.
- [ ] 새 인증 버전 검증 후 공개 범위 재검토. 현재는 팀원 IP 제한 유지.
- [ ] 필요한 경우 테스트 데이터 초기화 스크립트 추가. 현재는 미구현.
- [ ] 자동 기동·장기 중지 후 인증서 갱신·호환 가능한 버전으로의 롤백 검증.
- [ ] 필요 시 DuckDNS IP 자동 갱신 구성. 현재는 수동 갱신 기준.

DB의 `DELETE`는 AUTO_INCREMENT를 초기화하지 않는다. 화면 건수와 고유 ID는 다르며, 삭제 후 ID가 이어지는 것은 정상이다. Kafka 메시지가 logId를 참조하므로 표시 번호를 위해 기존 ID를 재사용하지 않는다.

## 참고

- [Docker Ubuntu 설치](https://docs.docker.com/engine/install/ubuntu/)
- [Docker Compose 환경변수](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/)
- [MySQL 컨테이너 초기화](https://hub.docker.com/_/mysql)
- [EC2 중지·시작](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html)
- [Nginx WebSocket 프록시](https://nginx.org/en/docs/http/websocket.html)
- [로컬 실행 문서](05_infra_deployment.md)
