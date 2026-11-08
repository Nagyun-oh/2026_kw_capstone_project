package com.example.security_log_system.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

/**
 * AI 분석 요청 토픽 선언.
 *
 * <p>파티션 2개로 두면 AI 프로세스를 2개(같은 consumer group)까지 늘려 나눠 소비할 수 있다.
 * 메시지 키는 logId라 두 파티션에 고르게 나뉘며 요청 간 순서는 필요 없다.
 * 2026/11/08 AI 프로세스 2개로 운영 실험했지만 2 vCPU 서버 CPU가 이미 묶여 있어 지연이 줄지 않았다.
 * 그래서 AI 프로세스 기본값은 1로 되돌렸고(compose.aws.yaml AI_UVICORN_WORKERS), 소비자 1개가 두 파티션을
 * 모두 읽는다(트러블슈팅_8 2부).
 *
 * <p>운영 토픽은 이미 2개 파티션이다. 파티션은 줄일 수 없으므로 선언도 실제 상태와 같은 2로 유지한다.
 * 선언을 1로 바꾸면 KafkaAdmin이 기동할 때마다 파티션 수 불일치를 기록한다.
 */
@Configuration
public class AiRequestTopicConfig {

    public static final String AI_REQUEST_TOPIC = "ai-request-topic";

    public static final int AI_REQUEST_PARTITIONS = 2;

    @Bean
    public NewTopic aiRequestTopic() {
        return TopicBuilder.name(AI_REQUEST_TOPIC)
                .partitions(AI_REQUEST_PARTITIONS)
                .replicas(1)
                .build();
    }
}
