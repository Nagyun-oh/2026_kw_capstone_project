-- 기존 security_db에 공통 요청 ID 연결 구조 추가
-- 대상 DB를 선택한 상태에서 한 번만 실행한다.
-- 기존 network_logs의 request_id는 NULL로 유지된다.

ALTER TABLE network_logs
    ADD COLUMN request_id VARCHAR(255)
        CHARACTER SET utf8mb4
        COLLATE utf8mb4_0900_bin
        NULL,
    ADD CONSTRAINT uk_network_logs_request_id
        UNIQUE (request_id);

CREATE TABLE request_correlations (
    request_id VARCHAR(255)
        CHARACTER SET utf8mb4
        COLLATE utf8mb4_0900_bin
        NOT NULL,

    PRIMARY KEY (request_id)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_bin;

