package com.example.security_log_system.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

/**
 * AI 분석 요청 토픽 선언.
 *
 * <p>AI 서비스는 소비자 스레드 하나가 메시지를 한 건씩 직렬로 처리한다. 파티션이 1개면 소비자도 1개만
 * 동작해 2 vCPU 중 한 코어만 쓴다. 파티션을 2개로 두고 AI 프로세스 2개(같은 consumer group)가 나눠
 * 소비하게 한다(트러블슈팅_8 2부). 메시지 키는 logId라 두 파티션에 고르게 나뉘며 요청 간 순서는 필요 없다.
 *
 * <p>기존 토픽이 1개 파티션이면 KafkaAdmin이 기동 시 2개로 늘린다. 파티션은 줄일 수 없으므로,
 * 되돌릴 때는 AI 프로세스를 1개로 줄여 한 소비자가 두 파티션을 모두 읽게 한다.
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
