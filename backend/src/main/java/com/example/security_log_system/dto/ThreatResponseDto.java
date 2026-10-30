package com.example.security_log_system.dto;

import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.util.UtcDateTime;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;

@Getter
@Builder
public class ThreatResponseDto {

    private Long id;
    private Long logId;
    private String threatType;
    private String severity;
    private String description;
    private boolean checked;
    private OffsetDateTime detectedAt;

    public static ThreatResponseDto from(DetectedThreat threat){
        return ThreatResponseDto.builder()
                .id(threat.getId())
                .logId(threat.getLogEntry() !=null
                    ? threat.getLogEntry().getId() : null)
                .threatType(threat.getThreatType())
                .severity(threat.getSeverity())
                .description(threat.getDescription())
                .checked(threat.isChecked())
                .detectedAt(UtcDateTime.toOffset(threat.getDetectedAt()))
                .build();
    }
}
