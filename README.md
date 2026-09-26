# 웹 서버 보안 아키텍처 설계 및 구현

## 프로젝트 소개

보안 로그를 Kafka 기반 스트리밍 파이프라인으로 수집하고, Spring Boot 백엔드와 FastAPI AI 서비스가 로그를 분석해 위협 이벤트를 탐지한 뒤 React 대시보드에서 시각화하는 졸업 프로젝트입니다.


## 주요 기능

- WAF + Reverse Proxy 기반 외부 요청 필터링 및 라우팅 구조
- Kafka 기반 보안 로그 수집 및 비동기 처리
- FastAPI 기반 AI 추론 서비스 연동
- Spring Boot 백엔드의 로그, 위협, 블랙리스트 관리 API
- JWT 기반 관리자 인증
- MySQL 기반 로그 및 탐지 결과 저장
- React 대시보드에서 로그, 탐지 이벤트, 차단 IP 현황 표시
- WebSocket/STOMP 기반 실시간 알림 구조
- Swagger OpenAPI 문서 제공
- CodeQL, CycloneDX, OWASP Dependency-Check 기반 보안 품질 관리

## 시스템 아키텍처

<img src="docs/images/img.png" alt="시스템 아키텍처" width="900" height="400">

## 기술 스택

| 영역 | 기술 |
| --- | --- |
| Backend | Java 17, Spring Boot 3.5, Spring Web, Spring Security, Spring Data JPA, Spring Kafka |
| AI Service | Python, FastAPI, scikit-learn 기반 모델 |
| Frontend | React, Axios, STOMP, SockJS |
| Database | MySQL |
| Message Broker | Apache Kafka |
| Infra | Docker, Docker Compose, Windows local development , AWS|
| Quality | Swagger OpenAPI, CodeQL, CycloneDX SBOM, OWASP Dependency-Check |

## 프로젝트 구조

```
├── backend/              # Spring Boot 백엔드
├── frontend/             # React 대시보드
├── AI/                   # FastAPI AI 분석 서비스
├── docs/                 # 문서 목록
├── dev_tools/            # 테스트 도구 및 개발 보조 스크립트
├── waf/                  # WAF 관련 실험/문서
├── targets/              # 테스트 대상 또는 실험 리소스
└── .github/workflows/    # GitHub Actions, CodeQL workflow
```

## 로컬 실행 방법

루트 [compose.yaml](compose.yaml)로 백엔드·프론트엔드·AI·MySQL·Kafka·Zookeeper·WAF·JuiceShop·Fluent Bit를 함께 실행합니다. 명령은 프로젝트 루트의 Windows PowerShell 기준입니다.

**현재 구성은 기존 로컬 MySQL 데이터, Kafka·Zookeeper 볼륨, `security-net` 네트워크를 재사용합니다.** 신규 PC에서 저장소만 복제하면 바로 실행되는 구성은 아닙니다. `.env` 설정, AI 모델 준비, 저장 공간 확인을 먼저 진행하세요.

자세한 준비·실행·중지·재빌드·검증·문제 해결 절차는 [인프라 및 실행 문서](docs/05_infra_deployment.md)를 참고하세요.

준비와 기존 컨테이너 전환이 끝난 환경에서는 다음 명령을 사용합니다.

```powershell
docker compose --env-file .env -f compose.yaml config --quiet
docker compose --env-file .env -f compose.yaml up -d --build
docker compose --env-file .env -f compose.yaml ps -a
```

| 용도 | 접속 주소 |
| --- | --- |
| 대시보드 | http://localhost:3000 |
| WAF를 통한 JuiceShop | http://localhost |
| 백엔드 상태 | http://localhost:8080/actuator/health |
| 백엔드 Swagger | http://localhost:8080/swagger-ui/index.html |
| AI 상태 / Swagger | http://localhost:8000/health / http://localhost:8000/docs |

기존 하위 Compose와 루트 Compose를 동시에 실행하지 마세요. 컨테이너 이름·포트가 겹치며, 동일한 DB·Kafka 저장 공간을 두 서버에서 동시에 사용하면 안 됩니다. 현재 WAF는 `DetectionOnly`이며 대시보드의 블랙리스트 등록이 WAF 자동 차단을 의미하지 않습니다.

## AWS 배포

[compose.aws.yaml](compose.aws.yaml)을 사용하는 단일 EC2 개발·시연 배포 절차는 [AWS 배포 및 운영 문서](docs/06_aws_deployment.md)를 참고하세요. 코드·AI 모델 전달, 실제 환경변수 설정, DB 초기화, WAF 디렉터리 권한, 서비스 검증, EC2 중지·재시작 절차를 포함합니다.

2026-09-26 사용자 실행 결과로 외부 접근·AI 결과 조회 및 재시작 후 데이터 보존을 확인했습니다. 현재는 보안 그룹으로 접근 IP를 제한하는 시연 환경입니다. EC2에서 수정한 Nginx 프록시 주소를 저장소에도 반영해야 하는 후속 항목은 해당 문서에 명시했습니다.

## 주요 API

| Method | Path | 설명 |
| --- | --- | --- |
| POST | `/api/v1/auth/login` | 관리자 로그인 및 JWT 발급 |
| POST | `/api/v1/auth/register` | 관리자 계정 생성 |
| GET | `/api/v1/logs` | 로그 목록 조회, pagination 적용 |
| GET | `/api/v1/logs/{id}` | 로그 번호별 검색 |
| GET | `/api/v1/threats` | 탐지된 위협 목록 조회 |
| POST | `/api/v1/threats/detect` | AI 탐지 결과 HTTP 수신, 보조/테스트용 |
| GET | `/api/v1/blacklist` | 블랙리스트 목록 조회 |
| POST | `/api/v1/blacklist` | IP 차단 등록 |
| DELETE | `/api/v1/blacklist/{id}` | 블랙리스트 항목 삭제 |

## 테스트 및 품질 점검

### Backend 테스트
```
cd backend
.\gradlew test
```

### Backend 컴파일 확인
```
cd backend
.\gradlew compileJava
```

### Gradle 의존성 확인
```
cd backend
.\gradlew dependencies --configuration runtimeClasspath
```

### SBOM 생성
```
cd backend
.\gradlew cyclonedxBom
```

생성 결과:
```
backend/build/reports/cyclonedx/bom.json
backend/build/reports/cyclonedx/bom.xml
```

### 오픈소스 취약점 분석
```
cd backend
$env:NVD_API_KEY="발급받은_NVD_API_KEY"
.\gradlew dependencyCheckAnalyze
```
NVD API Key는 필수는 아니지만, 없으면 취약점 DB 업데이트가 오래 걸릴 수 있습니다. API Key는 저장소에 커밋하지 않고 환경변수로만 관리합니다.
