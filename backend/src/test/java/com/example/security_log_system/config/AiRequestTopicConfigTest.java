package com.example.security_log_system.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AiRequestTopicConfigTest {

    @Test
    @DisplayName("AI 요청 토픽은 운영 토픽과 같은 파티션 2개로 선언한다(소비자 1~2개 모두 동작)")
    void aiRequestTopic_hasTwoPartitionsForTwoConsumers() {
        NewTopic topic = new AiRequestTopicConfig().aiRequestTopic();

        assertThat(topic.name()).isEqualTo("ai-request-topic");
        assertThat(topic.numPartitions()).isEqualTo(2);
        assertThat(topic.replicationFactor()).isEqualTo((short) 1);
    }
}
