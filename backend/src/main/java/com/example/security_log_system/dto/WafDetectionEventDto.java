package com.example.security_log_system.dto;


import com.example.security_log_system.validation.ValidIpAddress;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

// waf-detection-topic 으로 전달되는 요청 단위 WAF 탐지 이벤트
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class WafDetectionEventDto {

    @NotBlank(message = "Source is required.")
    @Pattern(
            regexp = "waf",
            message = "Source must be waf."
    )
    private String source;

    @JsonProperty("event_type")
    @NotBlank(message = "Event type is required.")
    @Pattern(
            regexp = "waf_detection",
            message = "Event type must be waf_detection."
    )
    private String eventType;

    @JsonProperty("request_id")
    @NotBlank(message = "Request ID is required.")
    @Size(max=255, message = "Request ID must not exceed 255 characters.")
    private String requestId;

    // ModSecurity의 원본 시각 문자열을 보존한다.
    @NotBlank(message = "Event time is required.")
    private String time;

    @JsonProperty("client_ip")
    @NotBlank(message = "Client IP is required.")
    @ValidIpAddress
    private String clientIp;

    // 알려진 HTTP 메서드 목록으로 제한하지 않는다.
    // 비정상 메서드 자체가 탐지 대상일 수 있다.
    @NotBlank(message = "HTTP method is required.")
    private String method;

    @NotBlank(message = "Request path is required.")
    private String path;

    @Min(value = 100, message = "HTTP status must be at least 100.")
    @Max(value= 599, message = "HTTP status must not exceed 599.")
    private Integer status;

    @JsonProperty("anomaly_score")
    @Min(value=0,message="Anomaly score must not be negative.")
    private Integer anomalyScore;

    @JsonProperty("matched_rules")
    @NotEmpty(message = "At least one matched rule is required.")
    @Valid
    private List<@NotNull(message = "Matched rule must not be null.") WafMatchedRuleDto> matchedRules;



}
