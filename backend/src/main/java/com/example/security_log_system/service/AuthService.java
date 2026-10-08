package com.example.security_log_system.service;

import com.example.security_log_system.dto.AuthRequestDto;
import com.example.security_log_system.entity.AdminUser;
import com.example.security_log_system.repository.AdminUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
public class AuthService {
    private final AdminUserRepository adminUserRepository; // 관리자 계정 DB 조회/저장
    private final PasswordEncoder passwordEncoder;         // 비밀번호 암호화 및 검증
    private final AuthenticationManager authenticationManager;
    private final SessionAuthenticationStrategy sessionAuthenticationStrategy; // 로그인 성공 시 세션 ID 변경, 기존 CSRF 토큰 초기화
    private final SecurityContextRepository securityContextRepository; // 인증 정보를 세션에 저장하고 이후 요청에서 복원

    public Authentication authenticate(AuthRequestDto request){
        UsernamePasswordAuthenticationToken loginRequest =
                UsernamePasswordAuthenticationToken.unauthenticated(
                        request.getUsername(),
                        request.getPassword()
                );
        return authenticationManager.authenticate(loginRequest);
    }

    // 계정 인증 후 로그인 상태를 HTTP 세션에 저장
    public Authentication loginWithSession(
            AuthRequestDto loginRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ){
        // 1. 아이디·비밀번호 검증
        // 실패하면 예외가 발생하므로 아래 저장 과정은 실행되지 않음
        Authentication authentication = authenticate(loginRequest);

        // 2. 로그인 성공 시 세션 보호 처리
        // 기존 세션 ID 변경 + 기존 CSRF 토큰 초기화
        sessionAuthenticationStrategy.onAuthentication(authentication,request,response);

        // 3. 이번 로그인 결과를 담을 새로운 보안 context 생성
        SecurityContext context =
                SecurityContextHolder.createEmptyContext();

        context.setAuthentication(authentication);

        // 4. 현재 요청에서 로그인한 사용자로 인식하도록 설정
        SecurityContextHolder.setContext(context);

        // 5. 다음 요청에서도 로그인 상태를 복원할 수 있도록 세션에 저장
        securityContextRepository.saveContext(
                context,
                request,
                response
        );

        return authentication;
    }


    /*
      회원가입 성공하면 true, 중복이면 false
    * */
    @Transactional
    public boolean registerAdmin(AuthRequestDto request){
        if(adminUserRepository.findByUsername(request.getUsername()).isPresent()){
            return false;
        }

        AdminUser user = AdminUser.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role("ROLE_ADMIN")
                .build();

        adminUserRepository.save(user);
        return true;
    }

}

/*
    로그인 요청
      → 계정 검증
      → 세션 ID 변경·기존 CSRF 토큰 초기화
      → 인증 정보를 세션에 저장
      → 브라우저가 세션 쿠키 보관

    이후 API 요청
      → 브라우저가 세션 쿠키 전송
      → 서버가 세션에서 인증 정보 조회
      → 관리자 권한 검사
* */