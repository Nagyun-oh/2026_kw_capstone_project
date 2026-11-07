package com.example.security_log_system.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;


@Entity                             // 이 클래스가 JPA 엔티티임을 선언, 즉 이 클래스는 DB테이블과 1:1로 매핑되는 객체
@Table(                             // 이 엔티티가 DB의 어느 테이블에 저장될지 지정
        name = "network_logs",
        // 전체 로그 목록의 created_at 내림차순 페이지 조회가 테이블 전체를 읽고 정렬하지 않도록 한다.
        // ddl-auto=validate는 인덱스를 만들거나 검사하지 않으므로 기존 DB에는 docs/db SQL로 적용한다.
        indexes = @Index(name = "idx_network_logs_created_at", columnList = "created_at")
)
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