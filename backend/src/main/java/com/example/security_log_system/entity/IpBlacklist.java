package com.example.security_log_system.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "ip_blacklist")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class IpBlacklist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "source_threat_id")
    private DetectedThreat sourceThreat;

    @Column(name = "ip_address",length = 45, nullable = false)
    private String ipAddress;

    @Column(length = 255)
    private String reason;

    @Column(name = "danger_level")
    private int dangerLevel;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "expired_at")
    private LocalDateTime expiredAt;

}

/*
TODO
    - ipAddress에 unique 제약 추가 검토
    - dangerLevel 범위 명확화, 예: 1~5
    - expiredAt 사용 정책 문서화 또는 자동 만료 로직 추가
    - createdAt 자동 설정 방식으로 변경 검토
    - reason null 허용 여부 결정
*/