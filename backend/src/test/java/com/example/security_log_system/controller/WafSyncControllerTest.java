package com.example.security_log_system.controller;

import com.example.security_log_system.config.SecurityConfig;
import com.example.security_log_system.config.WafSyncSecurityConfig;
import com.example.security_log_system.dto.BlacklistSnapshotDto;
import com.example.security_log_system.service.BlacklistSnapshotService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

@WebMvcTest
@ContextConfiguration(classes = {
        WafSyncController.class,
        WafSyncSecurityConfig.class,
        SecurityConfig.class
})
@TestPropertySource(properties = {
        "app.cors.allowed-origins=http://localhost:3000",
        "app.waf-sync.token=test-only-waf-sync-token-0123456789"
})
public class WafSyncControllerTest {

    private static final String TOKEN =
            "test-only-waf-sync-token-0123456789";
    private static final String URL =
            "/internal/waf/blacklist";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private BlacklistSnapshotService blacklistSnapshotService;

    @Test
    @DisplayName("올바른 동기화 토큰으로 전체 차단 목록을 조회한다")
    void validTokenReturnsSnapshot() throws Exception {
        when(blacklistSnapshotService.getSnapshot())
                .thenReturn(new BlacklistSnapshotDto(
                        "snapshot-version",
                        List.of("203.0.113.20")
                ));

        mockMvc.perform(get(URL)
                        .header("X-WAF-Sync-Token",TOKEN))
                .andExpect(status().isOk())
                .andExpect(header().string(
                        "Cache-Control","no-store"
                ))
                .andExpect(jsonPath("$.version")
                        .value("snapshot-version"))
                .andExpect(jsonPath("$.ipAddresses[0]")
                        .value("203.0.113.20"));
    }

    @Test
    @DisplayName("토큰이 없으면 401을 반환하고 목록을 조회하지 않는다")
    void missingTokenIsRejected() throws Exception{
        mockMvc.perform(get(URL))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(blacklistSnapshotService);
    }

    @Test
    @DisplayName("잘못된 토큰이면 401을 반환한다")
    void wrongTokenIsRejected() throws Exception{
        mockMvc.perform(get(URL)
                        .header("X-WAF-Sync-Token","wrong-token"))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(blacklistSnapshotService);
    }

    @Test
    @DisplayName("관리자 인증만으로 동기화 API를 사용할 수 없다")
    void adminWithoutSyncTokenIsRejected() throws Exception {
        mockMvc.perform(get(URL)
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(blacklistSnapshotService);
    }

    @Test
    @DisplayName("동기화 토큰으로 관리자 API에 접근할 수 없다")
    void syncTokenDoesNotGrantAdminAccess() throws Exception {
        mockMvc.perform(get("/api/v1/blacklist")
                        .header("X-WAF-Sync-Token", TOKEN))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("올바른 토큰이 있어도 동기화 경로의 POST는 거부한다")
    void writeRequestIsRejected() throws Exception {
        mockMvc.perform(post(URL)
                        .header("X-WAF-Sync-Token", TOKEN)
                        .with(csrf()))
                .andExpect(status().isForbidden());

        verifyNoInteractions(blacklistSnapshotService);
    }

    @Test
    @DisplayName("기존 관리자 삭제 API는 여전히 CSRF 토큰을 요구한다")
    void adminDeleteStillRequiresCsrf() throws Exception {
        mockMvc.perform(delete("/api/v1/blacklist/1")
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isForbidden());
    }


}
