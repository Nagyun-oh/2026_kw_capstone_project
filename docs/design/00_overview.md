# 00. 프로젝트 개요

이 문서는 DualGuard의 목적·범위·팀 역할·확정 기술 스택·저장소 구조를 한곳에 정리하고, 설계 문서를 읽는 순서를 안내한다.

최종 확인: 2026/11/08 · 기준: `develop`(PR #113 AI 판정 근거 표시 포함). 버전은 아래에 적은 파일에서 직접 확인한 값이다.

## 1. 목적과 해결하려는 문제

DualGuard(저장소 제목: "웹 서버 보안 아키텍처 설계 및 구현")는 WAF와 AI 탐지를 결합한 졸업 프로젝트다. 테스트 웹 서버(OWASP Juice Shop) 앞에 WAF를 두고, 같은 HTTP 요청을 규칙(ModSecurity CRS)과 AI 모델(3모델 앙상블) 두 계층에서 판정한다. 결과는 요청 단위로 묶어 관리자 대시보드에 보여 준다.

| 문제 | 대응 | 근거 |
| --- | --- | --- |
| 한 계층만으로는 공격을 다 잡지 못한다. 공격 시나리오 18건 중 둘 다 탐지 10건, WAF만 탐지 5건, 둘 다 미탐 3건 | 같은 요청을 WAF·AI가 각각 판정하고 둘 다 기록한다 | [시나리오 카탈로그](../testing/scenario_catalog.md) 7장 |
| WAF만으로 자동 차단하면 정상 사용자도 막힌다. 정상 입력 10건 중 WAF 오탐 7건, AI 오탐 0건 | 같은 요청에서 WAF·AI가 모두 탐지하고 IP도 일치할 때만 자동 차단한다 | 시나리오 카탈로그 8.5절, [AGENTS.md](../../AGENTS.md) |
| 두 판정이 따로 남으면 같은 요청인지 대조하기 어렵다 | WAF가 만든 `request_id`로 HTTP 로그·WAF 탐지·AI 탐지를 연결하고, 요청 단위 목록과 통합 알림을 제공한다 | AGENTS.md "보존해야 할 동작" |
| AI 분석이 웹 요청 처리 경로에 들어가면 응답이 모델 처리에 묶인다 | WAF 로그를 수집한 뒤 Kafka로 비동기 분석한다. 분석 결과로 이미 처리된 요청을 소급 차단하지 않는다 | AGENTS.md "실제 구조와 데이터 흐름" |
| 점수만 보여 주면 관리자가 판정을 검토하기 어렵다 | AI 판정 출처(규칙/모델)와 기여 피처·근거 위치를 화면에 표시한다 | [AI_new/README.md](../../AI_new/README.md) 9장 |

운영 목표는 "수초 안의 모니터링"이다. 서버 경로 p95 3초는 프로젝트가 정한 공학적 목표이며 산업 표준·운영 SLA가 아니다([P8](../testing/ec2/P8.md)).

## 2. 범위

| 포함 | 제외·범위 밖 |
| --- | --- |
| WAF를 거쳐 Juice Shop으로 들어오는 HTTP 요청의 접근 로그 수집·저장·검색 | 일반 공격 규칙의 인라인 차단. WAF는 `DetectionOnly`이고 블랙리스트 IP만 403 |
| AI 비동기 탐지(규칙 게이트 + 3모델)와 WAF 탐지 저장 | AI 분석·블랙리스트 등록으로 이미 실행된 요청을 소급 차단하는 것 |
| 요청 단위 통합 위협 목록, 커밋 후 실시간 알림(WebSocket/STOMP) | WebSocket 알림의 종단 간 exactly-once 보장 |
| 수동·자동 블랙리스트, WAF 차단 동기화와 적용 상태 표시 | 다중 인스턴스·고가용성·자동 확장(단일 EC2 개발·시연 환경) |
| 관리자 세션 인증·CSRF, 내부 API 토큰 인증, AI 판정 근거 표시 | 트랜스포머 모델 학습 파이프라인(저장소 외부) |
| 로컬 Compose·단일 EC2 배포, GitHub Actions CI/CD | 탐지율·오탐률·공격 유형별 판정 검증(보안 팀원 범위, 서버 성능 측정과 분리) |
| EC2 처리량·지연·정합성 측정과 병목 개선 기록 | XXE처럼 두 계층이 함께 놓치는 사각지대 대응(시나리오 카탈로그 6번, 향후 과제) |

## 3. 팀 역할

초기 프로젝트 개요(2026/05/07 작성)의 분담이다.

| 이름 | 역할 |
| --- | --- |
| 오나균(팀장) | 프론트엔드·백엔드 개발, 인프라 구축, 전체 아키텍처 설계, 최종 발표 |
| 김진섭 | 보안 오픈 데이터셋 탐색·정제, 테스트 시나리오 작성, 보안 아키텍처 설계, 최종 발표 |
| 남현욱 | AI 모델 개발, 데이터 분석, 중간 발표 |

현재 저장소 문서에 적힌 작업 경계는 다음과 같다.

- 탐지율·오탐률·공격 유형별 판정은 보안 팀원이 검증한다([테스트 공통 가이드](../testing/README.md)).
- `AI_new/` 코드는 AI 담당 팀원 영역이라 성능 개선에서 수정하지 않는 것을 전제로 한다([단계 부하 계획](../testing/ec2/step-load-plan.md) 1절).
- 서버 처리량·지연·자원·적체·정합성 측정과 개선은 [EC2 목차](../testing/ec2/README.md)에 기록한다.

## 4. 확정 기술 스택과 버전

| 영역 | 기술 | 버전 | 확인 위치 |
| --- | --- | --- | --- |
| 백엔드 | Java | 17(빌드 `eclipse-temurin:17-jdk-jammy`, 실행 `17-jre-jammy`) | [build.gradle](../../backend/build.gradle), [Dockerfile](../../backend/Dockerfile) |
| 백엔드 | Spring Boot(Web·Security·Data JPA·WebSocket·Validation·Actuator), Spring Kafka, Spring Security Messaging | Boot 3.5.11, dependency-management 1.1.7. 스타터·Kafka 버전은 Boot BOM 관리 | build.gradle |
| 백엔드 | springdoc-openapi(Swagger UI), Micrometer Prometheus, MySQL Connector/J, Lombok | springdoc 2.8.17, 나머지 BOM 관리 | build.gradle |
| 백엔드 | Gradle Wrapper | 8.14.4 | `backend/gradle/wrapper/gradle-wrapper.properties` |
| 프론트 | React, react-dom, Create React App(`react-scripts`) | 19.2.4, 19.2.4, 5.0.1 | [package-lock.json](../../frontend/package-lock.json) 설치 버전 |
| 프론트 | axios, @stomp/stompjs, sockjs-client, react-toastify | 1.18.0, 7.3.0, 1.6.1, 11.0.5 | package-lock.json |
| 프론트 | 빌드·제공 이미지 | `node:22-alpine` → `nginx:stable-alpine` | [Dockerfile](../../frontend/Dockerfile) |
| AI | Python, FastAPI, uvicorn, pydantic | 3.12(`python:3.12-slim-bookworm`), 0.111.0, 0.30.1, 2.7.4 | [requirements.txt](../../AI_new/requirements.txt), [Dockerfile](../../AI_new/Dockerfile) |
| AI | scikit-learn, pandas, torch(CPU 휠), shap, kafka-python-ng | 1.8.0, 2.2.2, 2.8.0, 0.54.1, 2.2.3 | requirements.txt |
| AI | 모델 | 트랜스포머 + HistGradientBoosting 트리(28피처) + 스키마 전문가(12피처), 로짓 소프트보팅 가중치 0.05/0.85/0.10, 임계값 0.965 | AI_new/README.md 2장 |
| DB | MySQL | `mysql:8.0` | [compose.aws.yaml](../../compose.aws.yaml) |
| 메시징 | Kafka, Zookeeper | `confluentinc/cp-kafka:7.3.0`, `cp-zookeeper:7.3.0` | compose.aws.yaml |
| WAF | Nginx + ModSecurity CRS | `owasp/modsecurity-crs:nginx`(태그만 지정, 세부 버전 고정 없음) | compose.aws.yaml |
| 수집 | Fluent Bit | `fluent/fluent-bit:2.2` | compose.aws.yaml |
| 대상 | OWASP Juice Shop | `bkimminich/juice-shop`(태그 미지정) | compose.aws.yaml |
| 운영 | EC2 t3.large(2 vCPU/8GiB), Ubuntu 24.04 LTS, 호스트 Nginx + Certbot | — | [AWS 배포](../operations/aws_deployment.md) |
| CI/CD·품질 | GitHub Actions(`ci.yml`·`codeql.yml`·`deploy.yml`), Amazon ECR, AWS SSM, OWASP Dependency-Check, CycloneDX | Gradle 플러그인 12.2.2, 3.2.4 | [.github/workflows](../../.github/workflows/), build.gradle |

로컬 [compose.yaml](../../compose.yaml)도 같은 인프라 이미지 태그를 쓴다. 앱 이미지는 로컬에서 `security-*:local`로 빌드하고, EC2에서는 ECR의 `security-*:<git SHA>`를 받는다.

## 5. 저장소 구조

```text
.
├── backend/              Spring Boot: REST API, Kafka 소비, outbox·알림 발행, WAF 동기화 API
├── frontend/             React 대시보드, 운영 Nginx 설정(nginx.conf)
├── AI_new/               FastAPI AI 서비스: 3모델 앙상블·판정 근거, 모델 lock
├── waf/                  Nginx/ModSecurity 템플릿·규칙, Fluent Bit 설정, 블랙리스트 동기화, 테스트
├── targets/              WAF 뒤에 둘 대상 앱 실행 예시(Juice Shop)
├── scripts/              deploy.sh(EC2 배포), fetch_models.py(모델 받기·해시 검증), testing/(E2E·EC2 측정 실행기)
├── dev_tools/            개발 보조 스크립트
├── docs/
│   ├── design/           설계 근거(이 문서 묶음)
│   ├── operations/       로컬 실행·AWS 배포·CI/CD 절차
│   ├── testing/          실험 가이드, 로컬·EC2 회차 보고서·증거
│   ├── db/               새 DB 스키마와 기존 DB용 추가 SQL
│   └── images/ · security/ · archive/
├── compose.yaml          로컬 Compose
├── compose.aws.yaml      EC2 Compose
├── .env.example · aws.env.example   환경 변수 예제(자리표시자)
└── .github/workflows/    ci.yml · codeql.yml · deploy.yml
```

백엔드 Java 소스의 기준 경로는 `backend/src/main/java/com/example/security_log_system/`이다.

## 6. 문서 읽는 순서

1. [00 개요](00_overview.md) — 목적·범위·스택(이 문서)
2. [01 요구사항](01_requirements.md) — 기능·비기능 요구사항과 검증 결과 추적
3. [02 아키텍처](02_architecture.md) — 구성 요소, 데이터 흐름, 배포 구조, 자원 제약
4. [03 이벤트 파이프라인](03_event_pipeline.md) — Kafka 토픽·outbox·재시도/DLT
5. [04 탐지](04_detection.md) — WAF·AI 탐지와 요청 연결, 판정 근거
6. [05 WAF 동기화](05_waf_sync.md) — 블랙리스트 적용·상태 보고
7. [06 백엔드](06_backend.md) · [07 데이터베이스](07_database.md) · [08 보안](08_security.md)
8. 운영: [로컬 Compose](../operations/local_compose.md) → [AWS 배포](../operations/aws_deployment.md) → [CI/CD](../operations/cicd.md)
9. 검증: [시나리오 카탈로그](../testing/scenario_catalog.md), [EC2 테스트 목차](../testing/ec2/README.md)

DB 구조는 [새 DB 스키마](../db/security-db-schema.sql)와 07 문서를 함께 본다.

## 결정 · 대안 · 근거

| 결정 | 검토한 대안 | 선택 근거 | 관련 문서·코드 |
| --- | --- | --- | --- |
| 백엔드 Spring Boot + AI FastAPI + React로 역할별 서비스 분리 | 초기 개요(2026/05)의 백엔드 후보 "Spring Boot 또는 FastAPI" 중 하나로 통일 | 모델이 Python(scikit-learn·PyTorch) 생태계에서 학습·서빙되고 AI 팀원이 따로 관리한다. 인증·트랜잭션·Kafka 소비·알림은 Spring에 둔다 | [AI_new/README.md](../../AI_new/README.md), [build.gradle](../../backend/build.gradle) |
| WAF 일반 규칙은 `DetectionOnly`, 블랙리스트 IP만 403 | CRS 차단 모드로 공격 요청 즉시 차단 | WAF·AI 비교를 위해 CRS 판정은 기록만 한다. 정상 입력 10건 중 7건이 WAF 오탐이라 차단 모드는 정상 사용자를 막을 위험이 있다 | [waf/README.md](../../waf/README.md), [시나리오 카탈로그](../testing/scenario_catalog.md) 8장 |
| AI는 `AI_new` 3모델 앙상블(규칙 게이트 병행) | 이전 4모델(RF/ET/XGB/HGB) 앙상블 | 4모델 pkl은 3GB를 넘었고 트리+스키마 결합 pkl은 13.75MB다. 출처 식별 지름길 피처를 빼고 규칙 게이트로 드문 공격 패턴을 보완했다 | AI_new/README.md 1·2장, [이전 모델 기록](../archive/ai-v1/README.md) |
| AI 판정 근거는 판정을 바꾸지 않는 사후 설명(TreeSHAP)으로 추가 | 근거 없이 점수·규칙 문구만 표시 | 탐지 여부·점수·임계값은 그대로 두고 표시만 바꾼다. 탐지 1건당 약 6ms이며 정상 요청에는 계산하지 않는다 | AI_new/README.md 9장, [04 탐지](04_detection.md) |
