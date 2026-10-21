package com.example.security_log_system.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;


@Entity                             // 이 클래스가 JPA 엔티티임을 선언, 즉 이 클래스는 DB테이블과 1:1로 매핑되는 객체
@Table(name = "network_logs")       // 이 엔티티가 DB의 어느 테이블에 저장될지 지정
@Getter                             // 모든 필드에 대한 Getter메서드 자동 생성
@NoArgsConstructor                  // 파라미터가 없는 기본 생성자를 생성
@AllArgsConstructor                 // 모든 필드를 파라미터로 받는 생성자를 생성
@Builder                            // 빌더 패턴 사용할 수 있게 설정. (new LogEntry().. 같은 생성자 형태 대신 사용)
public class LogEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id",length = 255, unique=true)
    private String requestId;

    private String ipAddress;       // 접속한 IP
    private String requestMethod;   // GET, POST 등

    @Column(name="request_url",columnDefinition = "TEXT")
    private String requestUrl;      // 긴 요청 경로와 쿼리 문자열 저장

    private int statusCode;         // 200,403 등

    @Column(columnDefinition = "TEXT")
    private String rawLog;          // 전체 원본 로그
    private LocalDateTime createdAt; // 로그 수신 시간

}

/*
TODO
    - 필드에 @Column(name = "...")를 명시해서 DB 컬럼명 통일성 확보
    - createdAt 자동 설정을 위해 @PrePersist 또는 Auditing 적용 검토
    - statusCode가 0으로 저장될 수 있는 케이스 검토
    - AI 처리 상태(PENDING, COMPLETED, FAILED) 필드 추가 검토
    - DetectedThreat와 양방향 관계가 필요한지 검토
*/