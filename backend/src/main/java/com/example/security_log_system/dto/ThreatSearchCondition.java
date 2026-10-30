package com.example.security_log_system.dto;


import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

// 위협 검색 조건
@Getter
@Setter
@NoArgsConstructor
public class ThreatSearchCondition {

    @Min(value = 1,message = "Threat ID must be at least 1.")
    private Long threatId;

    private String threatType;

    @Pattern(
            regexp = "AI|WAF",
            message = "Source must be AI or WAF."
    )
    private String source;

    @Pattern(
            regexp = "(?i)(LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN)",
            message = "Invalid severity."
    )
    private String severity;


}
