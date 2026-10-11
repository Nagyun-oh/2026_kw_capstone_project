package com.example.security_log_system.controller;


import com.example.security_log_system.dto.ThreatDto;
import com.example.security_log_system.dto.ThreatResponseDto;
import com.example.security_log_system.dto.ThreatSearchCondition;
import com.example.security_log_system.exception.GlobalExceptionHandler;
import com.example.security_log_system.service.ThreatService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.*;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ThreatControllerTest {

    @Mock
    private ThreatService threatService;

    private MockMvc mockMvc;

    // 각 테스트 메서드가 실행되기 전에 매번 호출됨.
    @BeforeEach
    void setup() {

        // @Valid, @NotBlank, @ValidIpAddress 등을 실행할 Validator를 생성하고 초기화한다.
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();

        // mock Service를 주입해서 테스트 대상 Controller를 직접 생성한다.
        ThreatController controller = new ThreatController(threatService);

        mockMvc = MockMvcBuilders.standaloneSetup(controller)       // 해당 Controller만 테스트 환경에 등록
                .setControllerAdvice(new GlobalExceptionHandler())  // Validation 예외를 GlobalExceptionHandler가 처리하도록 등록
                .setValidator(validator)                            // DTO 검증에 사용할 Validator 등록
                .build();                                           // MockMvc 생성
    }

    @Test
    @DisplayName("위협 검색 조건과 페이지 정보를 Service에 전달한다")
    void getThreats_whenConditionIsValid_thenReturnPage() throws Exception{

        Pageable pageable = PageRequest.of(
                0,
                20,
                Sort.by(Sort.Direction.DESC, "detectedAt")
        );

        ThreatResponseDto threat = ThreatResponseDto.builder()
                .id(1L)
                .logId(10L)
                .threatType("SQL Injection")
                .severity("CRITICAL")
                .description("SQL injection pattern detected")
                .checked(false)
                .detectedAt(OffsetDateTime.parse("2026-10-07T02:57:52Z"))
                .build();

        Page<ThreatResponseDto> result = new PageImpl<>(List.of(threat),pageable,1);

        when(threatService.getThreats(
                any(ThreatSearchCondition.class),
                eq(pageable)))
                .thenReturn(result);

        mockMvc.perform(get("/api/v1/threats")
                        .param("page", "0")
                        .param("size", "20")
                        .param("severity","CRITICAL")
                        .param("threatType","SQL"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(1))
                .andExpect(jsonPath("$.content[0].logId").value(10))
                .andExpect(jsonPath("$.content[0].threatType")
                        .value("SQL Injection"))
                .andExpect(jsonPath("$.content[0].severity")
                        .value("CRITICAL"))
                .andExpect(jsonPath("$.content[0].checked")
                        .value(false))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.size").value(20))
                .andExpect(jsonPath("$.number").value(0));

        ArgumentCaptor<ThreatSearchCondition> captor =
                ArgumentCaptor.forClass(ThreatSearchCondition.class);

        verify(threatService).getThreats(captor.capture(),eq(pageable));
        assertThat(captor.getValue().getThreatType()).isEqualTo("SQL");
        assertThat(captor.getValue().getSeverity()).isEqualTo("CRITICAL");
    }

    // 2. 정상적인 ThreatDto 요청이 Service까지 전달되는지 검사
    @Test
    @DisplayName("유효한 위협 탐지 요청 시 서비스에 요청 정보를 전달하고 200 OK를 반환한다")
    void receiveDetect_whenRequestIsValid_thenReturnOk() throws Exception{

        // JSON형식의 POST 요청 전송
        mockMvc.perform(post("/api/v1/threats/detect")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "threatType": "SQL Injection",
                                  "clientIp": "192.168.0.10",
                                  "dangerLevel": 4,
                                  "description": "SQL injection detected"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        "Threat recorded successfully."
                ));


        ArgumentCaptor<ThreatDto> captor = ArgumentCaptor.forClass(ThreatDto.class);

        verify(threatService).saveDetectedThreat(captor.capture());

        ThreatDto request = captor.getValue();

        assertThat(request.getThreatType())
                .isEqualTo("SQL Injection");
        assertThat(request.getClientIp())
                .isEqualTo("192.168.0.10");
        assertThat(request.getDangerLevel())
                .isEqualTo(4);
        assertThat(request.getDescription())
                .isEqualTo("SQL injection detected");

    }

    // 3. 잘못된 요청 테스트
    @Test
    @DisplayName("유효하지 않은 위협 탐지 요청 시 검증 오류와 400 Bad Request를 반환하고 서비스는 호출되지 않는다\"")
    void receiveDetect_whenRequestIsInvalid_thenReturnBadRequest() throws Exception {

        mockMvc.perform(post("/api/v1/threats/detect")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "threatType": "",
                                  "clientIp": "999.999.999.999",
                                  "dangerLevel": 10,
                                  "description": ""
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message")
                        .value("Request validation failed."))
                .andExpect(jsonPath("$.errors.threatType")
                        .value("Threat type is required."))
                .andExpect(jsonPath("$.errors.clientIp")
                        .value("Invalid IPv4 or IPv6 address."))
                .andExpect(jsonPath("$.errors.dangerLevel")
                        .value("Danger level must not exceed 5."))
                .andExpect(jsonPath("$.errors.description")
                        .value("Description is required."));

        verifyNoInteractions(threatService);
    }

    @Test
    @DisplayName("Client IP가 비어 있으면 400 Bad Request를 반환한다")
    void receiveDetect_whenClientIpIsBlank_thenReturnBadRequest() throws Exception{

        mockMvc.perform(post("/api/v1/threats/detect")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                            "threatType" : "SQL Injection",
                            "clientIp" : "",
                            "dangerLevel":4,
                            "description": "SQL Injection detected"
                        }
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.clientIp")
                        .value("Client IP is required."));

        verifyNoInteractions(threatService);
    }

    @Test
    @DisplayName("심각도가 유효하지 않은 값이면, 400 Bad Request를 반환한다")
    void getThreats_whenSeverityIsInvalid_thenReturnBadRequest() throws Exception{

        mockMvc.perform(get("/api/v1/threats")
                .param("severity","UNKNOWN"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.severity")
                        .value("Invalid severity."));

        verifyNoInteractions(threatService);
    }

    @Test
    @DisplayName("위험도가 1보다 작으면 400 Bad Request를 반환한다")
    void receiveDetect_whenDangerLevelIsLessThanOne_thenReturnBadRequest() throws  Exception{

        mockMvc.perform(post("/api/v1/threats/detect")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                            "threatType" : "SQL Injection",
                            "clientIp" : "192.168.0.10",
                            "dangerLevel":0,
                            "description": "SQL Injection detected"
                        }
                        
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.dangerLevel")
                        .value("Danger level must be at least 1."));

        verifyNoInteractions(threatService);
    }




}

 /*   정상 조회:
        MockMvc GET
        → ThreatController
        → mock ThreatService
        → Page 반환
        → JSON 내용 검증

    정상 등록:
        MockMvc POST
        → DTO 변환 및 Validation 통과
        → Controller
        → mock ThreatService 호출
        → 200 OK

    잘못된 등록:
        MockMvc POST
        → DTO 변환
        → Validation 실패
        → GlobalExceptionHandler
        → 400 응답
        → Service 호출 없음
*/