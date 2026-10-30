package com.example.security_log_system.entity;


import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "waf_detections",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_waf_detections_request_id",
                        columnNames = "request_id"
                ),
                @UniqueConstraint(
                        name = "uk_waf_detections_threat_id",
                        columnNames = "threat_id"
                )

        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class WafDetection {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", nullable =false,length = 255)
    private String requestId;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "threat_id",nullable = false,unique = true)
    private DetectedThreat detectedThreat;

    @Column(name = "client_ip",nullable=false,length = 45)
    private String clientIp;

    @Column(
            name = "request_method",
            nullable = false,
            columnDefinition = "TEXT"
    )
    private String requestMethod;

    @Column(
            name = "request_path",
            nullable = false,
            columnDefinition = "TEXT"
    )
    private String requestPath;

    @Column(name = "response_status")
    private Integer responseStatus;

    @Column(name = "anomaly_score")
    private Integer anomalyScore;

    @Column(
            name = "matched_rules_json",
            nullable = false,
            columnDefinition = "LONGTEXT"
    )
    private String matchedRulesJson;

    @Column(
            name = "event_time_raw",
            nullable = false,
            columnDefinition = "TEXT"
    )
    private String eventTimeRaw;

    @JdbcTypeCode(SqlTypes.LOCAL_DATE_TIME)
    @Column(name = "occurred_at")
    private LocalDateTime occurredAt;

    @JdbcTypeCode(SqlTypes.LOCAL_DATE_TIME)
    @Column(name = "received_at", nullable=false)
    private LocalDateTime receivedAt;
}
