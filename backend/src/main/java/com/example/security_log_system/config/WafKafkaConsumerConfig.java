package com.example.security_log_system.config;


import com.example.security_log_system.exception.InvalidWafEventException;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.TopicPartition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.util.backoff.FixedBackOff;

@Configuration
@ConditionalOnProperty(
        prefix = "app.kafka.waf",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = false
)
public class WafKafkaConsumerConfig {

    public static final String DLT_TOPIC = "waf-detection-topic.DLT";

    @Bean
    public NewTopic wafDetectionDltTopic(){
        // 현재 단일 Kafka 브로커 구성 기준
        return TopicBuilder.name(DLT_TOPIC)
                .partitions(1)
                .replicas(1)
                .build();
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String,String>
    wafKafkaListenerContainerFactory(
            ConsumerFactory<String, String> consumerFactory,
            KafkaTemplate<String, String> kafkaTemplate
    ){
        // 처리에 실패한 Kafka 메시지를 DLT라는 별도 토픽으로 보내는 객체 생성
        DeadLetterPublishingRecoverer recoverer =
                new DeadLetterPublishingRecoverer(
                        kafkaTemplate,
                        (record,exception) ->
                                new TopicPartition(DLT_TOPIC,-1)
                );

        // DLT 전송 실패를 복구 성공으로 처리하지 않는다.
        recoverer.setFailIfSendResultIsError(true);

        // 최초 실행 후 최대 2회 추가 재시도, 재시도 간격 1초
        DefaultErrorHandler errorHandler = new DefaultErrorHandler(
                recoverer,
                new FixedBackOff(1000L,2L)
        );

        // 입력 오류는 재시도하지 않고 DLT로 전달한다.
        errorHandler.addNotRetryableExceptions(InvalidWafEventException.class);

        ConcurrentKafkaListenerContainerFactory<String,String> factory =
                new ConcurrentKafkaListenerContainerFactory<>();

        factory.setConsumerFactory(consumerFactory);
        factory.setCommonErrorHandler(errorHandler);

        // Kafka의 주기적 자동 커밋 대신 Listener 처리 결과에 맞춰 커밋한다.
        factory.getContainerProperties()
                .getKafkaConsumerProperties()
                .setProperty(
                        ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG,
                        "false"
                );

        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.RECORD);

        return factory;
    }

}

/*
    정상 이벤트
      → 검증 → 저장 담당 코드 → 완료

    잘못된 입력
      → 재시도 없이 waf-detection-topic.DLT

    저장 처리 오류
      → 최초 시도 + 추가 2회
      → 계속 실패하면 waf-detection-topic.DLT

    DLT 전송까지 실패
      → 복구 성공으로 처리하지 않고 다시 오류 처리
* */