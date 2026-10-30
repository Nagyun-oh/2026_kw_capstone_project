package com.example.security_log_system.dto;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;

// FastAPI -> Spring DTO
@Getter
@NoArgsConstructor
public class AiResponseDto {

    @JsonProperty("log_id")
    private Long logId;

    @JsonProperty("threat_score")
    private float threatScore;

    @JsonProperty("ip_address")
    private String ipAddress;

    @JsonProperty("reason")
    private String reason;
}
