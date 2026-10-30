package com.example.security_log_system.service;


import com.example.security_log_system.dto.AiRequestDto;
import com.example.security_log_system.dto.LogResponseDto;
import com.example.security_log_system.dto.LogSearchCondition;
import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.kafka.AiRequestProducer;
import com.example.security_log_system.repository.LogRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
public class LogServiceTest {

    @Mock
    private LogRepository logRepository;

    @Mock
    private BlacklistService blacklistService;

    @Mock
    private AiRequestProducer aiRequestProducer;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @InjectMocks
    private LogService logService;

    @Mock
    private RequestCorrelationService requestCorrelationService;

    @Test
    @DisplayName("유효한 Nginx 로그 수신 시 로그를 파싱하여 저장하고 AI 분석 요청을 전송한다")
    void validNginxLogMessage_thenParseAndSaveLogEntry(){
        // given
        String message = "{\"log\":\"127.0.0.1 - - [07/May/2026:16:00:00 +0900] \\\"GET /admin HTTP/1.1\\\" 403\"}";

        // NullPointerException 에러 방지용 코드
        when(logRepository.save(any(LogEntry.class)))
                .thenAnswer(invocation -> {
                    LogEntry logEntry = invocation.getArgument(0);
                    ReflectionTestUtils.setField(logEntry,"id",1L);
                    return logEntry;
                });


        ArgumentCaptor<LogEntry> logCaptor = ArgumentCaptor.forClass(LogEntry.class);
        ArgumentCaptor<AiRequestDto> aiCaptor = ArgumentCaptor.forClass(AiRequestDto.class);

        // when
        logService.processRawLog(message);

        // then
        verify(logRepository).save(logCaptor.capture());

        LogEntry savedLog = logCaptor.getValue();
        assertThat(savedLog.getIpAddress()).isEqualTo("127.0.0.1");
        assertThat(savedLog.getRequestMethod()).isEqualTo("GET");
        assertThat(savedLog.getRequestUrl()).isEqualTo("/admin");
        assertThat(savedLog.getStatusCode()).isEqualTo(403);

        verify(aiRequestProducer).sendAnalysisRequest(aiCaptor.capture());

        AiRequestDto aiRequestDto = aiCaptor.getValue();
        assertThat(aiRequestDto.getLogId()).isEqualTo(1L);
        assertThat(aiRequestDto.getIpAddress()).isEqualTo("127.0.0.1");
        assertThat(aiRequestDto.getMethod()).isEqualTo("GET");
        assertThat(aiRequestDto.getUrlPath()).isEqualTo("/admin");

    }

    @Test
    @DisplayName("빈 로그 메시지 수신 시 로그를 저장하거나 AI 분석을 요청하지 않는다")
    void emptyLogMessage_thenDoNothing(){
        // given
        String message = "{\"log\":\"\"}";

        // when
        logService.processRawLog(message);

        // then
        verify(logRepository,never()).save(any());
        verify(aiRequestProducer,never()).sendAnalysisRequest(any());
    }

   @Test
   @DisplayName("검색 조건으로 로그를 조회하고 Entity Page를 DTO Page로 변환한다")
   void getLogs_thenReturnDtoPage(){
       LogSearchCondition condition = new LogSearchCondition();
       condition.setIp("192.168.0.10");
       condition.setMethod("GET");
       condition.setStatusCode(200);

       Pageable pageable = PageRequest.of(0,20);

       LogEntry log = LogEntry.builder()
               .id(1L)
               .ipAddress("192.168.0.10")
               .requestMethod("GET")
               .requestUrl("/admin")
               .statusCode(200)
               .createdAt(LocalDateTime.now())
               .build();

       Page<LogEntry> page = new PageImpl<>(List.of(log),pageable,1);

       when(logRepository.findAll(
               any(Specification.class),
               eq(pageable)
       )).thenReturn(page);

       Page<LogResponseDto> result = logService.getLogs(condition,pageable);

       assertThat(result.getTotalElements()).isEqualTo(1);
       assertThat(result.getContent().get(0).getIpAddress())
               .isEqualTo("192.168.0.10");
       assertThat(result.getContent().get(0).getRequestMethod())
               .isEqualTo("GET");

       verify(logRepository).findAll(
               any(Specification.class),
               eq(pageable)
       );
   }
}
