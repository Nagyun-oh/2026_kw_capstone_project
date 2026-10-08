package com.example.security_log_system.controller;


import com.example.security_log_system.dto.LogResponseDto;
import com.example.security_log_system.dto.LogSearchCondition;
import com.example.security_log_system.exception.GlobalExceptionHandler;
import com.example.security_log_system.service.LogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import org.springframework.data.jpa.domain.Specification;

@ExtendWith(MockitoExtension.class)
public class LogControllerTest {

    @Mock
    private LogService logService;

    private MockMvc mockMvc;

    // 각 테스트 메서드가 실행되기 전에 매번 호출됨.
    @BeforeEach
    void setup() {

        // @Valid, @NotBlank, @ValidIpAddress 등을 실행할 Validator를 생성하고 초기화한다.
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();

        // mock Service를 주입해서 테스트 대상 Controller를 직접 생성한다.
        LogController controller = new LogController(logService);

        mockMvc = MockMvcBuilders.standaloneSetup(controller)       // 해당 Controller만 테스트 환경에 등록
                .setControllerAdvice(new GlobalExceptionHandler())  // Validation 예외를 GlobalExceptionHandler가 처리하도록 등록
                .setValidator(validator)                            // DTO 검증에 사용할 Validator 등록
                .build();                                           // MockMvc 생성
    }
    
    @Test
    @DisplayName("로그 검색 조건과 페이지 정보를 Service에 전달한다")
    void getLogs_whenSearchConditionIsValid_thenReturnPage() throws Exception {
        Pageable pageable = PageRequest.of(
                0,20,
                Sort.by(Sort.Direction.DESC,"createdAt")
        );

        LogResponseDto log = createLogResponse("192.168.0.10");
        Page<LogResponseDto> result = new PageImpl<>(List.of(log),pageable,1);

        when(logService.getLogs(
                any(LogSearchCondition.class),
                eq(pageable)
        )).thenReturn(result);

        mockMvc.perform(get("/api/v1/logs")
                .param("ip","192.168.0.10")
                .param("method","GET")
                .param("statusCode","200")
                .param("page","0")
                .param("size","20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].ipAddress")
                        .value("192.168.0.10"))
                .andExpect(jsonPath("$.totalElements").value(1));

        ArgumentCaptor<LogSearchCondition> captor =
                ArgumentCaptor.forClass(LogSearchCondition.class);

        verify(logService).getLogs(captor.capture(),eq(pageable));

        assertThat(captor.getValue().getIp()).isEqualTo("192.168.0.10");
        assertThat(captor.getValue().getMethod()).isEqualTo("GET");
        assertThat(captor.getValue().getStatusCode()).isEqualTo(200);
    }


    @Test
    @DisplayName("잘못된 IP로 로그를 검색하면 400 Bad Request를 반환한다")
    void getLogs_whenIpIsInvalid_thenReturnBadRequest() throws Exception{

        mockMvc.perform(get("/api/v1/logs")
                .param("ip","999.999.999.999")
                .param("page","0")
                .param("size","20"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.ip")
                        .value("Invalid IPv4 or IPv6 address."));

        verifyNoInteractions(logService);

    }


    private LogResponseDto createLogResponse(String ipAddress){
        return LogResponseDto.builder()
                .id(1L)
                .ipAddress(ipAddress)
                .requestMethod("GET")
                .requestUrl("/admin")
                .statusCode(200)
                .rawLog("sample log")
                .createdAt(OffsetDateTime.parse("2026-10-07T02:57:52Z"))
                .build();
    }
}
/*

    1. 전체 로그 조회 성공
    2. 유효한 IPv4/IPv6 검색 성공
    3. Service에 pagination 정보가 정확히 전달되는지
    4. 잘못된 IP로 로그를 검색하면 400 Bad Request를 반환한다

    MockMvc GET 요청
    → LogController
    → mock LogService
    → 테스트용 Page 반환
    → JSON 변환
    → 상태 코드와 응답 필드 검증
    → Service 호출 인자 검증
*/
