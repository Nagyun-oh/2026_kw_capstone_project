# AI 요청·결과 정합성 및 복구 검증

[로컬 목차](README.md)

## 범위

기존 `security_db`의 테이블 구조만 전용 `dg_recovery_<시각>` 스키마로 복제한다. 데이터는 복사하지 않는다. 실제 `LogService`·JPA·JDBC·outbox 발행기·결과 Consumer·재시도/DLT 처리기를 사용하고, Kafka는 테스트 JVM 안의 별도 KRaft 브로커를 사용한다. 실행 중인 애플리케이션 Kafka의 topic·group·offset은 조작하지 않는다.

이 검증의 실제 경계는 다음과 같다.

- 실제 MySQL 트랜잭션과 Kafka ACK, JDBC/JPA 저장, 프로세스 종료·재기동.
- 실제 TCP 실패: 테스트 producer만 닫힌 loopback 포트로 연결한 후 정상 브로커로 복구한다. Kafka 컨테이너 자체 중단·재기동은 아니다.
- 실제 JVM 종료: 테스트 전용 worker에서 `Runtime.halt`하고 새 JVM으로 재개한다. 기존 backend 컨테이너 재시작은 아니다.
- 중복 결과는 고정한 테스트 DTO를 두 번 넣는다. 실제 AI 추론을 실행한 결과로 설명하지 않는다.
- `AutoBlacklistPolicyService`·`NotificationService`·`SimpMessagingTemplate`은 대역이다. 자동 차단 정책·실제 웹소켓 전달·브라우저 DOM은 이 테스트의 검증 대상이 아니다.
- 프론트 hook의 중복·역전·닫기·재연결 처리는 소켓과 toast를 대역으로 둔 별도 단위 테스트다.

## 실행

루트 PowerShell에서 Docker의 `db` 서비스와 최소 1GiB 여유 메모리를 확인한 후 실행한다. Java 17·기존 Gradle 의존성 캐시가 필요하며 기존 DB에 outbox 스키마가 적용돼 있어야 한다.

```powershell
python .\scripts\testing\run_recovery_verification.py --execute --round 3
```

실행기는 새 실험 ID로 계획·원본을 먼저 만들고, 다음 사례를 순서대로 수행한다.

1. 같은 트랜잭션에서 로그·발행 대기 생성 후 강제 롤백: 양쪽 0건, 별도 트랜잭션에서 미커밋 작업 선점 불가.
2. 정상 커밋 후 발행: 실제 Kafka에 1건, outbox `SENT`.
3. 전송 접속 실패: `PENDING`·오류·재시도 시각 보존, 접속 복구 후 2번째 시도에 `SENT`.
4. 발행 전 worker 종료: 새 JVM이 `PENDING` 작업 발행.
5. 선점 직후 worker 종료: 실제 60초 리스 만료 후 새 JVM이 복구, 이전 token의 상태 갱신 거부.
6. ACK 후 `SENT` 저장 전 worker 종료: 브로커에 2건 재발행될 수 있으나 중복 결과 처리 후 탐지 1건·알림 revision 1 유지, 두 번 알림 발행을 호출해도 전송 경계 1회.
7. DLT 접속 실패: 원본 offset 전진 없음, 접속 복구 후 DLT 보존과 원본 커밋 확인.

35개 백엔드 테스트 중 7개가 위 통합 사례이고 28개는 관련 단위 테스트다. 7개 사례의 assertion·관측 증거가 모두 있어야 PASS다. 판정은 범위 내 정합성 검증에 한정한다.

프론트 단위 테스트:

```powershell
cd frontend
$env:CI = 'true'
npm test -- --watchAll=false --runInBand --no-cache --runTestsByPath src/hooks/useWebSocket.test.js
```

## 결과와 보존

- 보고서: `docs/testing/local/runs/<실험-ID>.md`
- 원본: `build/test-runs/<실험-ID>/`의 환경·소스 해시, events, observations, JUnit XML, worker 로그, 결과 JSON.
- 루트 DB 비밀번호는 메모리와 자식 프로세스 환경으로만 전달한다. 명령·원본 파일에 기록하지 않는다.
- 기존 DB는 구조·건수 조회만 수행한다. `DELETE`는 엄격히 이름을 제한한 테스트 스키마의 fixture에만 수행한다.
- 완료 후 테스트 스키마를 자동 삭제하지 않는다. 증거 검토 후 별도로 정리 여부를 결정한다.
- 메모리·10분 시간 상한·사용자 중단 시 소유한 테스트 프로세스 트리만 종료한다. 기존 컨테이너·볼륨은 종료·삭제하지 않는다.

격리 복구 r02 이후 같은 입력·측정 계약으로 실제 브라우저 **1건/초 × 120초 × 3회 r16~r18**를 수행해 모두 PASS했다. 추가 3·5건/초 각 1회 예비 확인도 완료했다. [로컬 목차](README.md)의 별도 회차와 연결하고, 이 격리 복구 테스트 자체를 실제 서비스 장애 중 브라우저 복구 검증으로 표현하지 않는다.
