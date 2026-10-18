CREATE TABLE request_alerts (
    alert_key VARCHAR(300)
        CHARACTER SET utf8mb4
        COLLATE utf8mb4_0900_bin
        NOT NULL,

    alert_id CHAR(36) NOT NULL,
    client_ip VARCHAR(45) NULL,

    waf_detected BOOLEAN NOT NULL DEFAULT FALSE,
    ai_detected BOOLEAN NOT NULL DEFAULT FALSE,
    alert_level INT NOT NULL DEFAULT 0,

    revision BIGINT NOT NULL DEFAULT 0,
    published_revision BIGINT NOT NULL DEFAULT 0,
    pending BOOLEAN NOT NULL DEFAULT FALSE,

    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,

    PRIMARY KEY (alert_key),
    CONSTRAINT uk_request_alerts_alert_id UNIQUE (alert_id),
    INDEX idx_request_alerts_pending (pending, updated_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_bin;