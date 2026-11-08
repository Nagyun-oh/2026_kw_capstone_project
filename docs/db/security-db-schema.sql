-- MySQL dump 10.13  Distrib 8.0.46, for Linux (x86_64)
--
-- Host: localhost    Database: security_db
-- ------------------------------------------------------
-- Server version	8.0.46

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `admin_users`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `admin_users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `role` varchar(20) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UK3fgxk4ewgaxgtgvqwb1jjudj6` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `detected_threats`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `detected_threats` (
  `is_checked` bit(1) DEFAULT NULL,
  `detected_at` datetime(6) DEFAULT NULL,
  `id` bigint NOT NULL AUTO_INCREMENT,
  `log_id` bigint DEFAULT NULL,
  `severity` varchar(10) DEFAULT NULL,
  `threat_type` varchar(50) DEFAULT NULL,
  `description` text,
  PRIMARY KEY (`id`),
  KEY `FKp5y1cn4hp7qs4ng46dmdb8aj1` (`log_id`),
  CONSTRAINT `FKp5y1cn4hp7qs4ng46dmdb8aj1` FOREIGN KEY (`log_id`) REFERENCES `network_logs` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ip_blacklist`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ip_blacklist` (
  `danger_level` int DEFAULT NULL,
  `created_at` datetime(6) DEFAULT NULL,
  `expired_at` datetime(6) DEFAULT NULL,
  `id` bigint NOT NULL AUTO_INCREMENT,
  `source_threat_id` bigint DEFAULT NULL,
  `ip_address` varchar(45) NOT NULL,
  `reason` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FKgih3ksr4le14l43h4h4kojalo` (`source_threat_id`),
  CONSTRAINT `FKgih3ksr4le14l43h4h4kojalo` FOREIGN KEY (`source_threat_id`) REFERENCES `detected_threats` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `network_logs`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `network_logs` (
  `status_code` int NOT NULL,
  `created_at` datetime(6) DEFAULT NULL,
  `id` bigint NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(255) DEFAULT NULL,
  `raw_log` text,
  `request_method` varchar(255) DEFAULT NULL,
  `request_url` text,
  `request_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_network_logs_request_id` (`request_id`),
  KEY `idx_network_logs_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

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


/*
| 필드 | 역할 |
| `log_id` | 원본 로그와 연결. PK로 로그 하나당 작업 하나 보장 |
| `payload` | 나중에 재발행할 AI 요청 JSON |
| `state` | `PENDING` / `IN_FLIGHT` / `SENT` |
| `attempts` | 선점·발행 시도 횟수 |
| `lease_token` | 현재 처리자의 식별값. 이전 처리자가 상태를 덮어쓰는 것 방지 |
| `available_at` | 다음 재시도 시각 또는 처리 선점 만료 시각 |
| `last_error_code` | 실패 종류. 요청 본문·비밀값은 저장하지 않음 |
| `published_at` | Kafka 전송 성공을 확인하고 완료 처리한 시각 |
*/
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

-- 아래 세 테이블과 network_logs.request_id는 새 DB에서 이 파일 하나로 만들어지도록 포함했다.
-- 기존 DB에는 각각 add-request-correlation.sql, add-waf-detections.sql, add-request-alerts.sql을 한 번만 적용한다.

-- 요청 단위 상관관계 잠금 행 (RequestCorrelationService)
CREATE TABLE request_correlations (
    request_id VARCHAR(255)
        CHARACTER SET utf8mb4
        COLLATE utf8mb4_0900_bin
        NOT NULL,

    PRIMARY KEY (request_id)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_0900_bin;

-- WAF 탐지 상세 (WafDetectionWriter)
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

-- 요청별 통합 알림과 커밋 후 발행 대기 상태 (RequestAlertService)
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
