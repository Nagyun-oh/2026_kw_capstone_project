package com.example.security_log_system.config;


import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import java.util.HashMap;
import java.util.Map;

/* Kafka로 메시지를 송신하기 위한 Producer 설정 클래스 */

@Configuration
public class KafkaProducerConfig {

    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;

    @Value("${spring.kafka.consumer.group-id}")
    private String groupId;
    
    @Bean
    public ProducerFactory<String, String> producerFactory(){

        // Kafka Producer 설정 값을 담는 Map
        Map<String,Object> props = new HashMap<>();

        // 로컬 개발 환경에서 사용하는 Kafka broker 주소
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);

        // Kafka 메시지는 내부적으로 byte 데이터로 저장되기 때문에 Java 객체로 바꿔야 한다.
        // StringDeserializer는 Kafka에서 받은 byte 데이터를 String으로 변환한다.
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        return new DefaultKafkaProducerFactory<>(props);
    }

    // Producer 설정을 기반으로 Factory 생성.
    @Bean
    public KafkaTemplate<String,String> kafkaTemplate(){
        return new KafkaTemplate<>(producerFactory());
    }
}