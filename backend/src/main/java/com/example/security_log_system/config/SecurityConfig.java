package com.example.security_log_system.config;


import com.example.security_log_system.security.JwtFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/* Spring Security의 인증·인가 정책과 JWT 필터, API 접근 권한을 설정하는 클래스 */

@Configuration
@EnableWebSecurity          // Spring Security 활성화
@RequiredArgsConstructor    // final 필드 생성자 자동 생성
public class SecurityConfig {

    private final JwtFilter jwtFilter;
    @Value("${app.cors.allowed-origins}")
    private List<String> allowedOrigins;

    // 어떤 요청을 허용/차단할지에 대한 보안 규칙 설정
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CORS 설정을 적용, React 프론트엔드가 localhost:3000에서 백엔드 localhost:8080으로 요청할 수 있게 해주는 부분이다.
                .cors(cors->cors.configurationSource(corsConfigurationSource()))
                // CSRF = 브라우저 기반 공격 방어기능인데
                // JWT 방식은 세션을 안쓰므로 필요 없음 -> 끄기
                .csrf(csrf -> csrf.disable())
                // 세션 사용 안함
                // 요청마다 토큰으로 본인 증명하니까, JWT는 서버가 로그인 상태를 기억 안해도 됨
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 요청별 권한 설정
                // TODO: 현재는 로그, 위협, 블랙리스트 API도 모두 permitAll()로 열려 있지만, 나중에 보호대상으로 바꿔야함.
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/v1/auth/**",      // 로그인/회원가입 -> 누구나 접근 가능
                                "/api/v1/logs/**",              // 임시 추가
                                "/api/v1/threats/**",           // 임시 추가
                                "/api/v1/blacklist/**",         // 임시 추가
                                "/ws-security/**",              // 임시 추가
                                "/swagger-ui/**",               // API 문서 -> 누구나 접근 가능
                                "/v3/api-docs/**",              // API 문서 -> 누구나 접근 가능
                                "/health",                      // 서버 상태 확인 -> 누구나 접근 가능
                                // 개발 환경에서 성능 지표 확인을 위해 Actuator endpoint를 허용함.
                                // 운영 환경에서는 Prometheus 서버 또는 관리자만 접근 가능하도록 제한해야 함.
                                "/actuator/health",
                                "/actuator/info",
                                "/actuator/metrics/**",
                                "/actuator/prometheus"
                        ).permitAll()                       // 위의 경로들은 토큰 없어도 허용
                        .anyRequest().authenticated()       // 나머지는 토큰 필수
                )
                // JWT 필터 등록
                // UsernamePasswordAuthenticationFilter 실행 전에 JwtFilter 먼저 실행
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // DB에 비밀번호 원문을 저장하지 않고 암호화된 값으로 저장할 때 사용한다.
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // 로그인 시 ID/PW 검증에 사용하는 AuthenticationManager를 Bean으로 등록한다.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
        return config.getAuthenticationManager();
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
