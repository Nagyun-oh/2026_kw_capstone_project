package com.example.security_log_system.dto;

import com.example.security_log_system.validation.ValidIpAddress;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class BlacklistSearchCondition {

    @ValidIpAddress
    private String ip;

    @Pattern(
            regexp = "(?i)MEDIUM|HIGH|CRITICAL",
            message = "Invalid severity."
    )
    private String severity;

    @Min(value=1,message= "Danger level must be at least 1.")
    @Max(value=5,message= "Danger level must not exceed 5.")
    private Integer dangerLevel;
}
