package com.example.security_log_system.entity;



import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name="detected_threats")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class DetectedThreat {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 1:N 관계 설정 (어떤 로그에서 발생했는지)
    @ManyToOne(fetch = FetchType.LAZY)  // 성능을 위해 사용
    @JoinColumn(name="log_id")
    @JsonIgnore
    private LogEntry logEntry;

    @Column(name = "threat_type" , length = 50)
    private String threatType;

    @Column(length = 10)
    private String severity; // HIGH, MEDIUM, LOW

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "is_checked")
    private boolean isChecked;

    @Column(name = "detected_at")
    private LocalDateTime detectedAt;


    public void linkLogEntry(LogEntry entry){
        if(entry == null || entry.getId() == null ){
            throw new IllegalArgumentException(
                    "Saved LogEntry is required."
            );
        }
        if(this.logEntry !=null
              && !this.logEntry.getId().equals(entry.getId())){
            throw new IllegalStateException("Threat is already linked to another log.");
        }
        this.logEntry = entry;
    }
}

