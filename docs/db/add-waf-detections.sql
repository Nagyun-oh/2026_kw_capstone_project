CREATE TABLE waf_detections (
    id BIGINT NOT NULL AUTO_INCREMENT,

    request_id VARCHAR(255)
        CHARACTER SET utf8mb4
        COLLATE utf8mb4_0900_bin
        NOT NULL,

    threat_id BIGINT NOT NULL,

    client_ip VARCHAR(45) NOT NULL,
    request_method TEXT NOT NULL,
    request_path TEXT NOT NULL,
    response_status INT NULL,

    anomaly_score INT NULL,
    matched_rules_json LONGTEXT NOT NULL,

    event_time_raw TEXT NOT NULL,
    occurred_at DATETIME(6) NULL,
    received_at DATETIME(6) NOT NULL,

    PRIMARY KEY (id),

    CONSTRAINT uk_waf_detections_request_id
        UNIQUE (request_id),

    CONSTRAINT uk_waf_detections_threat_id
        UNIQUE (threat_id),

    CONSTRAINT fk_waf_detections_threat
        FOREIGN KEY (threat_id)
        REFERENCES detected_threats (id),

    INDEX idx_waf_detections_occurred_at (occurred_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_ai_ci;