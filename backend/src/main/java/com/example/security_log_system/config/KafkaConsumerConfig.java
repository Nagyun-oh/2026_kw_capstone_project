package com.example.security_log_system.config;

import org.springframework.beans.factory.annotation.Value;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;

import java.util.HashMap;
import java.util.Map;

/* Kafka에서 메시지를 수신하기 위한 Consumer 설정 클래스 */

@Configuration
@EnableKafka
public class KafkaConsumerConfig {


    @Value("${spring.kafka.consumer.auto-offset-reset}")
    private String autoOffsetReset;

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${spring.kafka.consumer.group-id}")
    private String groupId;

    @Bean
    public ConsumerFactory<String, String> consumerFactory() {

        // Kafka Consumer 설정 값을 담는 Map
        Map<String, Object> props = new HashMap<>();

        // 로컬 개발 환경에서 사용하는 Kafka broker 주소
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);

        // 백엔드 로그 처리용 Consumer group.
        // 같은 group에 속한 Consumer들은 topic 메시지를 나누어 처리한다.
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);

        // 유효한 커밋 offset이 없을 때 사용할 시작 위치
        props.put(
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG,
                autoOffsetReset
        );

        // Kafka 메시지는 내부적으로 byte 데이터로 저장되기 때문에 Java 객체로 바꿔야 한다.
        // StringDeserializer는 Kafka에서 받은 byte 데이터를 String으로 변환한다.
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);

        return new DefaultKafkaConsumerFactory<>(props);
    }

    // Consumer 설정을 기반으로 Factory 생성.
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, String> factory = new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}