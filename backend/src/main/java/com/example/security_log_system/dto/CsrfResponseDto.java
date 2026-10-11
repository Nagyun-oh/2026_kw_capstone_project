package com.example.security_log_system.dto;

// 프론트에 토큰을 넣을 HTTP 헤더 이름과 토큰 값을 전달하는 객체
public record CsrfResponseDto(String headerName, String token) {
}
