# 데이터베이스 설계 문서

## 주요 테이블

### network_logs

| 컬럼명 | 타입 | 설명 |
|---|---|---|
| id | BIGINT AUTO_INCREMENT PRIMARY KEYLong | 로그 ID |
| ipAddress | BIGINT | 접속한 IP |
| requestMethod | VARCHAR | 요청 Method |
| requestUrl | VARCHAR | 접속경로 |
| statusCode | INT | 200,403 등 |
| rawLog | TEXT | 전체 원본 로그 |
| createdAt | TIMESTAMP | 로그 수신 시간 |

> network_logs 테이블은 원본 로그이다.

### detected_threats
| 컬럼명 | 타입 | 설명 |
|---|---|---|
| id | BIGINT | 탐지된 위협 데이터의 고유 ID |
| logEntry | BIGINT | 위협이 탐지된 원본 로그 ID |
| threatType | VARCHAR | 탐지된 위협 유형 |
| severity | VARCHAR | 위험도 수준, 예: HIGH,MEDIUM,LOW |
| description | TEXT | 탐지된 위협에 대한 상세 설명 |
| is_checked | TINYINT(1) | 관리자가 해당 위협을 확인했는지 여부 |
| detected_at | DATETIME(6) | 위협이 탐지된 시간 |

>detected_threats 테이블은 로그 분석 과정에서 탐지된 보안 위협 정보를 저장하기 위한 테이블이다. 원본 로그와 외래키 관계를 맺고 있으며, 위협 유형, 위험도, 상세 설명, 확인 여부, 탐지 시간을 함께 저장한다.

### ip_blacklist

| 컬럼명 | 타입 | 설명 |
|---|---|---|
| id | BIGINT | 차단된 위협 데이터의 고유 ID |
| ip_address | VARCHAR | 차단된 위협 데이터의 IP |
| reason | VARCHAR | 차단된 이유 |
| danger_level | int | 위험도 |
| created_at | TIMESTAMP | 차단된 시간 |
| expired_at | TIMESTAMP | 차단이 해제된 시간 |

> ip_blacklist 테이블은 차단된 ip들을 저장한 table이다.

## 테이블 설계 의도
- 원본 로그와 분석 결과를 분리하여 저장한다.
- 하나의 로그가 보안 이벤트로 분류될 수 있도록 network_logs를 참조한다.
- 추후 다양한 이벤트 유형을 추가할 수 있도록 threatType 컬럼을 사용한다.