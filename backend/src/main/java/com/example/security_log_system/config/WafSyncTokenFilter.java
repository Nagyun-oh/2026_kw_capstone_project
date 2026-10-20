package com.example.security_log_system.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

// WAF 스냅샷 토큰 검증 필터
public class WafSyncTokenFilter extends OncePerRequestFilter {

    private static final String HEADER_NAME = "X-WAF-Sync-Token";

    private final byte[] expectedToken;

    public WafSyncTokenFilter(String token){
        if(token != null && !token.isBlank() && token.length() < 32){
            throw new IllegalArgumentException(
                    "WAF_SYNC_TOKEN must contain at least 32 characters"
            );
        }

        this.expectedToken =
                token == null || token.isBlank()
                        ? new byte[0]
                        : token.getBytes(StandardCharsets.UTF_8);

    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException{

        String suppliedToken = request.getHeader(HEADER_NAME);

        if(!isValidToken(suppliedToken)){
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        var authentication =
                new UsernamePasswordAuthenticationToken(
                        "waf-sync",
                        null,
                        List.of(
                                new SimpleGrantedAuthority(
                                        "WAF_BLACKLIST_READ"
                                )
                        )
                );

        SecurityContext context =
                SecurityContextHolder.createEmptyContext();

        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        try{
            filterChain.doFilter(request,response);
        } finally {
            SecurityContextHolder.clearContext();
        }



    }

    private boolean isValidToken(String suppliedToken){
        if(expectedToken.length == 0 ||
            suppliedToken == null ||
            suppliedToken.isBlank()){
            return false;
        }
        return MessageDigest.isEqual(
                expectedToken,
                suppliedToken.getBytes(StandardCharsets.UTF_8)
        );
    }

}
