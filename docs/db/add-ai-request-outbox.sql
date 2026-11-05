CREATE TABLE ai_request_outbox (
    log_id BIGINT NOT NULL,
    payload MEDIUMTEXT NOT NULL,

    state VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    attempts BIGINT NOT NULL DEFAULT 0,

    lease_token CHAR(36) NULL,
    available_at DATETIME(6) NOT NULL,

    last_error_code VARCHAR(100) NULL,

    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    published_at DATETIME(6) NULL,

    PRIMARY KEY (log_id),

    INDEX idx_ai_outbox_ready (
        state,
        available_at,
        log_id
    ),

    CONSTRAINT fk_ai_outbox_log
        FOREIGN KEY (log_id)
        REFERENCES network_logs (id)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_bin;