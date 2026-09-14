package com.example.security_log_system.security;


import jakarta.servlet.FilterChain;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtFilterTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtFilter jwtFilter;

    @AfterEach
    void tearDown(){
        // 테스트 간 인증 정보가 공유되지 않도록 초기화
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("유효한 JWT가 있으면 인증 정보를 SecurityContext에 등록한다")
    void doFilter_whenTokenIsValid_thenSetAuthentication() throws Exception {

        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.addHeader("Authorization","Bearer valid-token");

        when(jwtUtil.validateToken("valid-token")).thenReturn(true);
        when(jwtUtil.extractUsername("valid-token")).thenReturn("admin");

        // when
        jwtFilter.doFilter(request,response,filterChain);

        // then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        assertThat(authentication).isNotNull();
        assertThat(authentication.getName()).isEqualTo("admin");
        assertThat(authentication.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ADMIN");

        verify(jwtUtil).validateToken("valid-token");
        verify(jwtUtil).extractUsername("valid-token");
        verify(filterChain).doFilter(request,response);
    }

    @Test
    @DisplayName("JWT가 유효하지 않으면 인증 정보를 등록하지 않는다")
    void doFilter_whenTokenIsInValid_thenSetAuthentication() throws Exception {

        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.addHeader("Authorization","Bearer invalid-token");

        when(jwtUtil.validateToken("invalid-token")).thenReturn(false);

        // when
        jwtFilter.doFilter(request,response,filterChain);

        // then
        Authentication authentication =
                    SecurityContextHolder.getContext().getAuthentication();

        assertThat(authentication).isNull();

        verify(jwtUtil).validateToken("invalid-token");
        verify(jwtUtil,never()).extractUsername(anyString());
        verify(filterChain).doFilter(request,response);

    }

    @Test
    @DisplayName("Authorization 헤더가 없으면 JWT 검증을 하지 않는다")
    void doFilter_whenAuthorizationHearIsMissing_thenContinueFilterChain() throws Exception {

        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when
        jwtFilter.doFilter(request,response,filterChain);

        // then
        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .isNull();

        verifyNoInteractions(jwtUtil);
        verify(filterChain).doFilter(request,response);
    }

    @Test
    @DisplayName("Bearer 형식이 아니면 JWT 검증을 하지 않는다")
    void doFilter_whenHeaderIsNotBearer_thenContinuedoFilterChain() throws Exception{

        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.addHeader("Authorization","Basic credentials");

        // when
        jwtFilter.doFilter(request,response,filterChain);

        // then
        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .isNull();

        verifyNoInteractions(jwtUtil);
        verify(filterChain).doFilter(request,response);
    }
}

/*
    Mock HTTP 요청 생성
    → Authorization 헤더 설정
    → JwtFilter 실행
    → JwtUtil의 동작을 Mockito로 지정
    → SecurityContext 인증 정보 확인
    → 다음 FilterChain이 실행됐는지 확인
* */