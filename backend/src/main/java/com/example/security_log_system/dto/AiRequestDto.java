package com.example.security_log_system.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

// Spring -> FastAPI DTO
@Getter
@Builder
public class AiRequestDto {

    @JsonProperty("log_id")
    private Long logId;

    private String method;

    @JsonProperty("url_path")
    private String urlPath;

    @JsonProperty("query_params")
    private String queryParams;

    @JsonProperty("body_content")
    private String bodyContent;

    @JsonProperty("user_agent")
    private String userAgent;

    @JsonProperty("ip_address")
    private String ipAddress;

    @JsonProperty("timestamp")
    private String timestamp;
}

/*

        method:             str         # "GET" | "POST" | "PUT" | "DELETE"
        url_path:           str         # "/tienda1/publico/login.jsp"
        query_params:       str = ""    # URL 파라미터 (?뒤)
        body_content:       str = ""    # POST body 내용
        user_agent:         str = ""    # User-Agent 헤더값
        ip_address:         str = ""    # 요청 IP  (ex. "192.168.0.10")
        timestamp:          str = ""    # 요청 시각 (ex. "2026-03-31T14:00:00")

*/
