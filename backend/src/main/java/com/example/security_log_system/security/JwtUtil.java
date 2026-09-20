package com.example.security_log_system.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.util.Date;

// @Component가 붙어 있어서 Spring Bean으로 등록됨 -> AuthController, JwtFilter에서 주입받아 사용할 수 있게 됨.
@Component
public class JwtUtil {

    private final SecretKey key;
    private final long expirationMs;

    public JwtUtil(@Value("${security.jwt.secret}") String secret,
                   @Value("${security.jwt.expiration-ms}") long expirationMs) {
        if(secret == null || secret.isBlank()){
            throw new IllegalArgumentException("JWT secret must not be blank");
        }

        if(expirationMs <=0){
            throw new IllegalArgumentException("JWT expiration must be greater than 0");
        }

        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.expirationMs = expirationMs;
    }

    // 토큰 생성
    // 결과: "eyJhbGciOiJIUzI1..." 같은 긴 문자열
    public String generateToken(String username){
        Date issuedAt = new Date();
        Date expiresAt = new Date(issuedAt.getTime() + expirationMs);

        return Jwts.builder()
                .subject(username)      // 토큰 안에 username 저장
                .issuedAt(new Date())   // 발급 시간
                .expiration(expiresAt) // 만료 시간 : 지금 + 24시간
                .signWith(key)          // 비밀키로 서명 (위조 방지)
                .compact();             // 문자열로 변환해서 반환
    }

    // 토큰에서 username 꺼내기
    public String extractUsername(String token){
        return Jwts.parser()
                .verifyWith(key)            // 비밀키로 서명 검증
                .build()
                .parseSignedClaims(token)   // 토큰 파싱
                .getPayload()
                .getSubject();              // subject(username) 꺼내기
    }

    // 토큰 검증
    // - 토큰이 정상이고, 서명이 맞고, 만료되지 않았으면 true
    // - 변조되었거나 만료되었거나 형식이 이상하면 false
    public boolean validateToken(String token){
        try{
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        }catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }
}
