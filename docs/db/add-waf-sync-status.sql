-- 대상 DB를 선택한 뒤 한 번 실행한다.
-- received_at은 UTC 기준으로 저장한다.

CREATE TABLE waf_sync_status (
    waf_id VARCHAR(64)
        CHARACTER SET utf8mb4
        COLLATE utf8mb4_0900_bin
        NOT NULL,
    report_json LONGTEXT NOT NULL,
    received_at DATETIME(6) NOT NULL,

    PRIMARY KEY (waf_id)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_bin;