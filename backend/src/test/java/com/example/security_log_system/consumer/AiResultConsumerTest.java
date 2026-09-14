package com.example.security_log_system.consumer;

import com.example.security_log_system.dto.AiResponseDto;
import com.example.security_log_system.kafka.AiResultConsumer;
import com.example.security_log_system.service.ThreatService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AiResultConsumerTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private ThreatService threatService;

    @InjectMocks
    private AiResultConsumer Consumer;

    @Test
    @DisplayName("AI 결과 메시지를 DTO로 변환하여 ThreatService에 전달한다")
    void consume_whenMessageIsValid_thenCallThreatService() throws Exception{

        // given
        String message = """
                {
                    "log_id":1,
                    "threat_score":0.9,
                    "ip_address":"192.168.0.10",
                    "reason":"SQL injection"
                }
                """;

        AiResponseDto response = mock(AiResponseDto.class);

        when(objectMapper.readValue(message,AiResponseDto.class)).thenReturn(response);

        // when
        Consumer.consume(message);

        // then
        verify(objectMapper).readValue(message, AiResponseDto.class);
        verify(threatService).saveAiDetectedThreat(response);
    }

    @Test
    @DisplayName("잘못된 JSON 메시지는 Service에 전달하지 않는다")
    void consume_whenJSONIsInValid_thenNotCallThreatService() throws Exception{

        // given
        String message = "invalid-json";

        when(objectMapper.readValue(message, AiResponseDto.class))
                .thenThrow(new JsonProcessingException(
                        "Invalid JSON") {});

        // when (예외가 외부로 던져지지 않고, Consumer 내부 catch가 예외 처리하는지 확인한다)
        assertThatCode( () -> Consumer.consume(message))
                .doesNotThrowAnyException();

        // then
        verifyNoInteractions(threatService);

    }

    @Test
    @DisplayName("Service 처리에 실패해도 Consumer 예외를 외부로 던지지 않는다.")
    void consume_whenServiceFails_thenDoNotPropagateException() throws Exception{

        // given
        String message = """
                {"log_id":1,"threat_score":0.9}
                """;

        AiResponseDto response = mock(AiResponseDto.class);

        when(objectMapper.readValue(message, AiResponseDto.class))
                .thenReturn(response);

        doThrow(new RuntimeException("Database error"))
                .when(threatService)
                .saveAiDetectedThreat(response);

        // when & then ((예외가 외부로 던져지지 않고, Consumer 내부 catch가 예외 처리하는지 확인한다))
        assertThatCode( () -> Consumer.consume(message))
                .doesNotThrowAnyException();

        verify(threatService).saveAiDetectedThreat(response);
    }
}

/*
    Kafka JSON 메시지
    → ObjectMapper.readValue()
    → AiResponseDto
    → ThreatService.saveAiDetectedThreat()
*/
