package com.example.security_log_system.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.NullSecurityContextRepository;

@Configuration
public class WafSyncSecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain wafSyncSecurityFilterChain(
            HttpSecurity http,
            @Value("${app.waf-sync.token:}") String token
    ) throws Exception{

                http
                        .securityMatcher("/internal/waf/**")
                        .sessionManagement(session -> session
                                .sessionCreationPolicy(
                                        SessionCreationPolicy.STATELESS
                                )
                        )
                        .securityContext(context -> context
                                .securityContextRepository(
                                        new NullSecurityContextRepository()
                                )
                        )
                        .requestCache(cache -> cache.disable())
                        .formLogin(form -> form.disable())
                        .httpBasic(basic -> basic.disable())
                        .logout(logout->logout.disable())

                        .authorizeHttpRequests(auth -> auth
                                .requestMatchers(
                                        HttpMethod.GET,
                                        "/internal/waf/blacklist"
                                )
                                        .hasAuthority("WAF_BLACKLIST_READ")
                                        .anyRequest().denyAll()
                        )
                        .exceptionHandling(exception -> exception
                                .authenticationEntryPoint(
                                        new HttpStatusEntryPoint(
                                                HttpStatus.UNAUTHORIZED
                                        )
                                )
                                .accessDeniedHandler((request,response,denied) ->
                                        response.setStatus(
                                                HttpStatus.FORBIDDEN.value()
                                        )
                                )
                        )
                        .addFilterBefore(
                                new WafSyncTokenFilter(token),
                                AnonymousAuthenticationFilter.class
                        );
                return http.build();
    }
}

/*
    /internal/waf/** 요청
        → 전용 토큰 인증
        → 관리자 세션은 사용하지 않음

    그 외 요청
        → 기존 SecurityConfig
        → 기존 관리자 로그인·CSRF 유지
* */
