package com.example.security_log_system.dto;

import com.example.security_log_system.validation.ValidIpAddress;
import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class BlacklistRequestDto {

    @NotBlank(message = "Ip address is required.")
    @ValidIpAddress
    private String ipAddress;

    @NotBlank(message= "Reason is required.")
    @Size(max = 255, message = "Reason must contain at most 255 characters.")
    private String reason;

    @Min(value = 1 , message = "Danger level must be at least 1.")
    @Max(value = 5 , message = "Danger level must not exceed 5.")
    @JsonAlias("dangerlevel")
    private int dangerLevel;
}