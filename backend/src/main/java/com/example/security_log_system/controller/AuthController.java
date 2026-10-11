package com.example.security_log_system.controller;

import com.example.security_log_system.dto.AuthRequestDto;
import com.example.security_log_system.dto.AuthUserResponseDto;
import com.example.security_log_system.dto.CsrfResponseDto;
import com.example.security_log_system.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // 로그인 전에도 조회 가능
    @GetMapping("/csrf")
    public CsrfResponseDto csrf(CsrfToken csrfToken){
        return new CsrfResponseDto(
                csrfToken.getHeaderName(),
                csrfToken.getToken()
        );
    }

    // 아이디·비밀번호 검증 후 세션에 인증 정보 저장
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody AuthRequestDto loginRequest,
            HttpServletRequest request,
            HttpServletResponse response
            ) {
        try {
            Authentication authentication = authService.loginWithSession(loginRequest,request,response);
            return ResponseEntity.ok(toUserResponse(authentication));
        } catch(AuthenticationException exception){
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password.");
        }
    }

    // SecurityConfig에서 관리자 인증이 필요한 경로로 보호됨
    @GetMapping("/me")
    public AuthUserResponseDto me(Authentication authentication){
        return toUserResponse(authentication);
    }

    // 기존 관리자만 호출할 수 있도록 SecurityConfig에서 보호
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody AuthRequestDto request){
            if(!authService.registerAdmin(request)){
                return ResponseEntity
                        .badRequest()
                        .body("Username already exists.");
            }
            return ResponseEntity.ok(
                    "Admin account created successfully."
            );
    }

    // Spring Security의 인증 정보에서 사용자 이름과 역할을 꺼내, 프론트에 전달할 DTO로 변환하는 코드
    private AuthUserResponseDto toUserResponse(Authentication authentication){

        String role = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .findFirst()
                .orElse("");

        return new AuthUserResponseDto(
                authentication.getName(),
                role
        );
    }
}


