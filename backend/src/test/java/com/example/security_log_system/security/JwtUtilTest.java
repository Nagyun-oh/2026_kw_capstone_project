package com.example.security_log_system.security;

import io.jsonwebtoken.Jwts;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtUtilTest {

    private final JwtUtil jwtUtil = new JwtUtil();

    @Test
    @DisplayName("JWT를 생성하면 username을 추출할 수 있다")
    void generateToken_thenExtractUsername(){

        String token = jwtUtil.generateToken("admin");
        String username = jwtUtil.extractUsername(token);

        assertThat(username).isEqualTo("admin");
    }

    @Test
    @DisplayName("정상 JWT는 유효성 검사를 통과한다")
    void validateToken_whenTokenIsValid_thenReturnTrue(){

        String token = jwtUtil.generateToken("admin");
        boolean result = jwtUtil.validateToken(token);

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("변조된 JWT는 유효성 검사에 실패한다")
    void validateToken_whenTokenIsTampered_thenReturnFalse(){

        String token = jwtUtil.generateToken("admin");

        int signatureStart = token.lastIndexOf(".") + 1;
        char replacement = token.charAt(signatureStart) == 'a' ? 'b' : 'a';

        String tamparedToken =
                token.substring(0,signatureStart) + replacement+token.substring(signatureStart+1);

        assertThat(jwtUtil.validateToken(tamparedToken)).isFalse();

    }

    @Test
    @DisplayName("만료된 JWT는 유효성 검사에 실패한다")
    void validateToken_whenTokenIsExpired_thenReturnFalse(){

        SecretKey key = (SecretKey) ReflectionTestUtils.getField(jwtUtil,"key");

        // 만료된 토큰 생성
        String expiredToken = Jwts.builder()
                .subject("admin")
                .issuedAt(new Date(System.currentTimeMillis() - 2000))  // 발급 시간: 2초전
                .expiration(new Date(System.currentTimeMillis() - 1000)) // 만료 시간: 1초전
                .signWith(key)
                .compact();

        assertThat(jwtUtil.validateToken(expiredToken)).isFalse();
    }

    @Test
    @DisplayName("JWT 형식이 아니면 유효성 검사에 실패한다")
    void validateToekn_whenTokenIsMalformed_thenReturnFalse(){

        assertThat(jwtUtil.validateToken("not-a-jwt")).isFalse();
    }
}

/*

* */