package com.example.security_log_system.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AiRequestTopicConfigTest {

    @Test
    @DisplayName("AI 요청 토픽은 AI 소비자 2개가 나눠 읽도록 파티션 2개로 선언한다")
    void aiRequestTopic_hasTwoPartitionsForTwoConsumers() {
        NewTopic topic = new AiRequestTopicConfig().aiRequestTopic();

        assertThat(topic.name()).isEqualTo("ai-request-topic");
        assertThat(topic.numPartitions()).isEqualTo(2);
        assertThat(topic.replicationFactor()).isEqualTo((short) 1);
    }
}
