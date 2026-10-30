package com.example.security_log_system.dto;

import com.example.security_log_system.validation.ValidIpAddress;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;

// AI서버 -> 백엔드 전송용
@Getter
@NoArgsConstructor
public class ThreatDto {

    @NotBlank(message= "Threat type is required.")
    private String threatType;

    @NotBlank(message= "Client IP is required.")
    @ValidIpAddress
    private String clientIp;

    @Min(value = 1, message = "Danger level must be at least 1.")
    @Max(value = 5, message = "Danger level must not exceed 5.")
    private int dangerLevel;

    @NotBlank(message = "Description is required.")
    private String description;
}
