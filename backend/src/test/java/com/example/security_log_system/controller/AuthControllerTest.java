package com.example.security_log_system.controller;

import com.example.security_log_system.exception.GlobalExceptionHandler;
import com.example.security_log_system.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.util.List;
import java.util.Optional;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class AuthControllerTest {

    @Mock
    private AuthService authService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp(){

        LocalValidatorFactoryBean validator =
                new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();

        AuthController authController = new AuthController(authService);
        mockMvc = MockMvcBuilders.standaloneSetup(authController)
                .setControllerAdvice(new GlobalExceptionHandler())
                .setValidator(validator)
                .build();
    }

    @Test
    @DisplayName("로그인 성공 시 사용자 정보와 200 OK를 반환한다")
    void login_whenSuccess_thenReturnToken() throws Exception{
        var authentication =
                UsernamePasswordAuthenticationToken.authenticated(
                        "admin",
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
                );

        when(authService.loginWithSession(any(),any(),any()))
                .thenReturn(authentication);

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                            "username": "admin",
                            "password": "1234"
                        } 
                        """)
        ).andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.role").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$.token").doesNotExist());

    }

    @Test
    @DisplayName("로그인 실패 시 오류 메시지와 401 Unauthorized를 반환한다")
    void login_whenFailed_thenReturnUnauthorized() throws Exception {

        when(authService.loginWithSession(any(),any(),any()))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                        """
                        {
                            "username": "admin",
                            "password":"wrong-password"
                        }
                        """))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(
                        "Invalid username or password."
                ));
    }

    @Test
    @DisplayName("빈 로그인 요청은 400 Bad Request를 반환한다")
    void login_whenUsernameAndPasswordAreBlank_thenReturnBadRequest() throws Exception {

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                         {
                            "username": "",
                            "password": ""
                         }
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message")
                        .value("Request validation failed."))
                .andExpect(jsonPath("$.errors.username")
                        .value("username is required."))
                .andExpect(jsonPath("$.errors.password")
                        .value("password is required."));

        verifyNoInteractions(authService);
    }


    @Test
    @DisplayName("회원가입 성공 시 성공 메시지와 200 OK를 반환한다")
    void register_whenSuccess_thenReturnOk() throws Exception {
        when(authService.registerAdmin(any())).thenReturn(true);

        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                            "username" : "admin",
                            "password" : "1234"
                        }
                        """))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Admin account created successfully.")));
    }

    @Test
    @DisplayName("중복된 아이디로 회원가입 시 오류 메시지와 400 Bad Request를 반환한다")
    void register_whenDuplicatedUsername_thenReturnBadRequest() throws Exception {
        when(authService.registerAdmin(any())).thenReturn(false);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "admin",
                                  "password": "1234"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Username already exists.")));
    }

    @Test
    @DisplayName("비밀번호가 누락된 회원가입 요청은 400 Bad Request를 반환한다.")
    void register_whenPasswordIsMissing_thenReturnBadRequest() throws Exception{

        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                            "username": "admin"
                        }
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password")
                        .value("password is required."));

        verifyNoInteractions(authService);

    }

}

/*
    AuthControllerTest
    - 로그인 성공 → 200 + token
    - 로그인 실패 → 401
    - 회원가입 성공 → 200
    - 중복 아이디 → 400
* */
