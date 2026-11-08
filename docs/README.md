# DualGuard 문서 지도

이 디렉터리의 문서를 목적별로 묶고, 질문마다 어느 문서를 열면 되는지 정리한다.

## 구조

```text
docs/
  README.md            이 문서 (문서 지도)
  design/              왜 이렇게 만들었나: 요구사항·구조·설계 결정
  operations/          어떻게 실행·배포하나: 로컬 Compose, AWS 운영, CI/CD
  testing/             무엇으로 검증했나: 시나리오 목록, 로컬·EC2 실험 기록, 트러블슈팅
  db/                  새 DB 초기화 스키마와 기존 DB용 변경 SQL
  security/            오픈소스 보안 점검 기록
  images/              문서용 그림
  archive/             더 이상 운영하지 않는 구성의 기록(이전 AI v1)
```

## 질문별로 찾기

| 알고 싶은 것 | 문서 |
| --- | --- |
| 프로젝트 목적·범위·기술 스택 | [design/00_overview.md](design/00_overview.md) |
| 기능·비기능 요구사항과 검증 결과 | [design/01_requirements.md](design/01_requirements.md) |
| 전체 구성 요소·데이터 흐름·배포 구조 | [design/02_architecture.md](design/02_architecture.md) |
| Kafka 토픽, 재시도·DLT, outbox, 커밋 후 알림 | [design/03_event_pipeline.md](design/03_event_pipeline.md) |
| WAF·AI 탐지, request_id 상관관계, 자동 차단 정책 | [design/04_detection.md](design/04_detection.md) |
| WAF 블랙리스트 동기화·상태 보고 API 계약 | [design/05_waf_sync.md](design/05_waf_sync.md) |
| 백엔드 계층·트랜잭션·인증·시간 규칙 | [design/06_backend.md](design/06_backend.md) |
| 테이블·제약·인덱스·마이그레이션 | [design/07_database.md](design/07_database.md) · [db/](db/) |
| 위협 모델·보안 통제·비밀 관리 | [design/08_security.md](design/08_security.md) · [security/oss-security-check.md](security/oss-security-check.md) |
| 로컬에서 실행·재빌드·문제 해결 | [operations/local_compose.md](operations/local_compose.md) |
| EC2 배포·운영·롤백 | [operations/aws_deployment.md](operations/aws_deployment.md) |
| CI와 배포 워크플로 설정 | [operations/cicd.md](operations/cicd.md) |
| 기능·장애·정책 시나리오 목록 | [testing/scenario_catalog.md](testing/scenario_catalog.md) |
| 실험 진행 규칙과 기록 양식 | [testing/README.md](testing/README.md) · [testing/experiment-template.md](testing/experiment-template.md) |
| 로컬 E2E 실험 기록 | [testing/local/README.md](testing/local/README.md) |
| EC2 성능 부하 테스트·트러블슈팅 1~8 | [testing/ec2/README.md](testing/ec2/README.md) |

## 읽는 순서

1. 처음 보는 사람: `design/00` → `02` → `03`·`04` 순서로 읽으면 무엇을 왜 만들었는지 따라갈 수 있다.
2. 실행·배포가 목적이면 `operations/`부터 연다.
3. 성능·장애 대응 근거가 필요하면 `testing/ec2/README.md`의 트러블슈팅 표에서 시작한다.

## 문서를 둘 위치

- 설계 결정과 그 근거(대안·선택 이유)는 `design/`의 해당 주제 문서에 쓴다. 문서마다 끝에 `결정 · 대안 · 근거` 표가 있다.
- 실행 명령·절차·롤백은 `operations/`에 쓴다. 설계 문서에는 절차를 복제하지 않고 링크한다.
- 실험 계획·결과·증거는 `testing/`의 환경별 목차(`local/`, `ec2/`)에 쓴다.
- 작업 규칙과 진입점은 루트의 [AGENTS.md](../AGENTS.md)에 있다.
