package com.example.security_log_system.config;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/* 세션 인증, CSRF 보호, API 접근 권한을 설정하는 클래스 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;

    // 어떤 요청을 허용/차단할지에 대한 보안 규칙 설정
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            SecurityContextRepository securityContextRepository,
            CsrfTokenRepository csrfTokenRepository
    ) throws Exception {
        http
                // CORS 설정을 적용, React 프론트엔드가 localhost:3000에서 백엔드 localhost:8080으로 요청할 수 있게 해주는 부분
                .cors(cors->cors.configurationSource(corsConfigurationSource()))
                // 변경 요청에 CSRF 토큰 검증 적용
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository)
                        .ignoringRequestMatchers("/ws-security/**")
                )
                // 필요한 경우에 세션 생성
                .sessionManagement( session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.IF_REQUIRED
                        )
                )
                // 인증 정보를 HTTP 세션에서 조회
                // 로그인 성공 시에는 직접 saveContext()를 호출
                .securityContext(context -> context
                        .securityContextRepository(securityContextRepository)
                        .requireExplicitSave(true)
                )
               // REST API이므로 로그인 페이지 이동용 요청 저장은 사용하지 않음
                .requestCache(cache -> cache.disable())

               // React 로그인 화면과 JSON 로그인 API를 사용할 예정
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())

                // 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/v1/auth/csrf",
                                "/actuator/health"
                        ).permitAll()

                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/v1/auth/login"
                        ).permitAll()

                        .anyRequest().hasRole("ADMIN")
                )

                // 인증·권한 오류 응답
                .exceptionHandling(exception ->exception
                        // 401 Unauthorized (보호된 API를 사용하려면 로그인 필요)
                        .authenticationEntryPoint(
                                new HttpStatusEntryPoint(
                                        HttpStatus.UNAUTHORIZED
                                )
                        )
                        // 403 Forbidden (권한 부족 또는 CSRF 검증 실패)
                        .accessDeniedHandler((request,response,denied) ->
                                response.setStatus(
                                        HttpStatus.FORBIDDEN.value()
                                )
                        )
                )

                // 로그아웃은 Spring Security 필터가 처리
                .logout(logout -> logout
                        .logoutUrl("/api/v1/auth/logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessHandler((request,response,authentication)
                -> response.setStatus(
                        HttpStatus.NO_CONTENT.value()
                                )
                        ).permitAll()
                );
        return http.build();
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public CsrfTokenRepository csrfTokenRepository(){
        return new HttpSessionCsrfTokenRepository();
    }

    // 다음 단계의 로그인 처리에서 명시적으로 호출할 전략
    // 기존 세션이 있다면 , 로그인 성공 시 세션 ID 변경
    // 로그인 전에 사용하던 CSRF 토큰 제거
    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy(CsrfTokenRepository csrfTokenRepository){
        return new CompositeSessionAuthenticationStrategy(List.of(
                new ChangeSessionIdAuthenticationStrategy(),
                new CsrfAuthenticationStrategy(csrfTokenRepository)
        ));
    }

    // DB에 비밀번호 원문을 저장하지 않고 암호화된 값으로 저장할 때 사용한다.
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // 로그인 시 ID/PW 검증에 사용하는 AuthenticationManager를 Bean으로 등록한다.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    // CORS 정책을 직접 등록 (Spring Security 필터 단계에서 CORS를 처리)
    // React 개발 서버 주소인 localhost:3000에서 오는 요청을 허용한다.
    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT","PATCH" ,"DELETE","OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",configuration);
        
        return source;
    }

}


/*
    브라우저 요청
        → CORS 처리
        → 세션의 인증 정보 확인
        → 필요한 요청에 CSRF 검증
        → 접근 권한 확인
        → 허용되면 Controller 실행
* */