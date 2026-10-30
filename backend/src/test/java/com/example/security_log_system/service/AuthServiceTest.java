package com.example.security_log_system.service;


import com.example.security_log_system.dto.AuthRequestDto;
import com.example.security_log_system.entity.AdminUser;
import com.example.security_log_system.repository.AdminUserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Optional;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    private AdminUserRepository adminUserRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private SessionAuthenticationStrategy sessionAuthenticationStrategy;

    @Mock
    private SecurityContextRepository securityContextRepository;

    @AfterEach
    void tearDown(){
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("로그인 성공 시 세션 보호 처리 후 인증 정보를 저장한다")
    void loginWithSession_whenSuccess_thenSaveContext(){
        AuthRequestDto loginRequest = loginRequest("admin","1234");

        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();

        var authentication = UsernamePasswordAuthenticationToken.authenticated(
                "admin",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

        when(authenticationManager.authenticate(any()))
                .thenReturn(authentication);

        var result = authService.loginWithSession(
                loginRequest,
                request,
                response
        );

        assertThat(result).isSameAs(authentication);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);

        ArgumentCaptor<SecurityContext> contextCaptor =
                ArgumentCaptor.forClass(SecurityContext.class);

        var order = inOrder(
                sessionAuthenticationStrategy,
                securityContextRepository
        );

        order.verify(sessionAuthenticationStrategy)
                .onAuthentication(authentication,request,response);

        order.verify(securityContextRepository)
                .saveContext(
                        contextCaptor.capture(),
                        same(request),
                        same(response)
                );

        assertThat(contextCaptor.getValue().getAuthentication()).isSameAs(authentication);
    }

    @Test
    @DisplayName("인증 실패 시 세션 보호 처리와 인증 정보 저장을 수행하지 않는다")
    void loginWithSession_whenFailed_thenDoNotSaveContext(){

        AuthRequestDto loginRequest =
                loginRequest("admin","wrong-password");

        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();

        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() ->
                authService.loginWithSession(
                        loginRequest,
                        request,
                        response
                )
        ).isInstanceOf(BadCredentialsException.class);

        verifyNoInteractions(sessionAuthenticationStrategy,securityContextRepository);
    }

    @Test
    @DisplayName("회원가입시 사용자 이름이 중복되지 않으면 비밀번호를 암호화하여 관리자를 저장하고 true를 반환한다")
    void registerAdmin_whenUsernameNotExists_thenSaveUserAndReturnTrue(){
        AuthRequestDto request = loginRequest("admin","1234");

        when(adminUserRepository.findByUsername("admin")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("1234")).thenReturn("encoded-password");

        boolean result = authService.registerAdmin(request);

        assertThat(result).isTrue();

        ArgumentCaptor<AdminUser> userCaptor = ArgumentCaptor.forClass(AdminUser.class);
        verify(adminUserRepository).save(userCaptor.capture());

        AdminUser savedUser = userCaptor.getValue();
        assertThat(savedUser.getUsername()).isEqualTo("admin");
        assertThat(savedUser.getPassword()).isEqualTo("encoded-password");
        assertThat(savedUser.getRole()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    @DisplayName("회원가입시 사용자 이름이 이미 존재하면 관리자를 저장하지 않고 false를 반환한다")
    void registerAdmin_whenUsernameExists_thenReturnFalse() {
        AuthRequestDto request = loginRequest("admin","1234");

        AdminUser existingUser = AdminUser.builder()
                .username("admin")
                .password("encoded-password")
                .role("ROLE_ADMIN")
                .build();

        when(adminUserRepository.findByUsername("admin")).thenReturn(Optional.of(existingUser));

        boolean result = authService.registerAdmin(request);

        assertThat(result).isFalse();

        verify(adminUserRepository).findByUsername("admin");
        verify(adminUserRepository,never()).save(any());
        verifyNoInteractions(passwordEncoder);

    }

    private AuthRequestDto loginRequest(String username, String password) {
        AuthRequestDto request = new AuthRequestDto();
        ReflectionTestUtils.setField(request, "username", username);
        ReflectionTestUtils.setField(request, "password", password);
        return request;
    }
}
