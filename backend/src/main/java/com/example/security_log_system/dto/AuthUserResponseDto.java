package com.example.security_log_system.dto;


/* 이 DTO는 로그인 성공과 /me 응답에서 사용 */

public record AuthUserResponseDto(String username, String role) {
}
