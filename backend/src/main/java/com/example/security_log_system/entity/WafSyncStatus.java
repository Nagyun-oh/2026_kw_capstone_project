package com.example.security_log_system.entity;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "waf_sync_status")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class WafSyncStatus {

    @Id
    @Column(name = "waf_id",length = 64,nullable = false)
    private String wafId;

    @Column(name = "report_json",columnDefinition = "LONGTEXT",nullable = false)
    private String reportJson;

    // UTC 기준
    @Column(name = "received_at",columnDefinition = "DATETIME (6)", nullable = false)
    private LocalDateTime receivedAt;

}
