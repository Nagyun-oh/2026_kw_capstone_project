package com.example.security_log_system.consumer;


import com.example.security_log_system.kafka.LogKafkaConsumer;
import com.example.security_log_system.service.LogService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

/* Kafka 메시지가 들어왔을 때 LogConsumer가 LogService로 넘기는지 확인*/
/* 즉, Consumer 계층이 Service 계층으로 메시지를 잘 전달하는지 확인하는 테스트 */

@ExtendWith(MockitoExtension.class)
public class LogConsumerTest {

    // 가짜 객체 생성
    @Mock
    private LogService logService;

    private LogKafkaConsumer logConsumer;

    private MeterRegistry meterRegistry;

    @BeforeEach
    void setUp(){
        meterRegistry = new SimpleMeterRegistry();

        logConsumer = new LogKafkaConsumer(
                logService,
                meterRegistry
        );
    }

    @Test
    @DisplayName("정상 로그 메시지를 처리하면 성공 Counter와 처리 시간 Timer가 기록된다.")
    void kafkaMessageReceived_thenCallLogService(){
        // given
        String message = """
                {"log":127.0.0.1 GET /admin 403}""
                """;

        // when
        logConsumer.consume(message);

        // then
        verify(logService).processRawLog(message);

        assertThat(meterRegistry.counter("security.logs.processed").count())
                .isEqualTo(1.0);
        assertThat(meterRegistry.find("security.kafka.consumer.failures").counter())
                .isNull();
        assertThat(meterRegistry.timer(
                "security.log.processing.duration",
                "result",
                "success"
        ).count()).isEqualTo(1);
    }

    @Test
    @DisplayName("로그 처리 중 예외가 발생하면 실패 Counter와 실패 처리 시간 Timer가 기록된다.")
    void consume_whenLogServiceFails_thenDoNotPropagateException(){

        // given
        String message = "invalid-log-message";

        doThrow(new RuntimeException("log processing failed"))
                .when(logService)
                .processRawLog(message);

        // when
        logConsumer.consume(message);

        // then
        verify(logService).processRawLog(message);

        assertThat(meterRegistry.counter("security.kafka.consumer.failures").count())
                .isEqualTo(1.0);
        assertThat(meterRegistry.find("security.logs.processed").counter())
                .isNull();

        assertThat(meterRegistry.timer(
                "security.log.processing.duration",
                "result",
                "failure"
        ).count()).isEqualTo(1);
    }
}
/*
consume(message)
    → logService.processRawLog(message) 호출
    → 성공 Counter 1 증가
    → 실패 Counter는 생성되지 않음
    → result=success Timer 기록

logService.processRawLog(message)에서 예외 발생
    → LogKafkaConsumer가 catch
    → 실패 Counter 1 증가
    → 성공 Counter는 생성되지 않음
    → result=failure Timer 기록

* */