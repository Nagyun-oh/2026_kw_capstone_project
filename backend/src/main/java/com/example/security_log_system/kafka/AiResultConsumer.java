package com.example.security_log_system.kafka;

import com.example.security_log_system.dto.AiResponseDto;
import com.example.security_log_system.service.ThreatService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;

// TODO: DLQ 처리 고민

@Slf4j
@Component
@RequiredArgsConstructor
public class AiResultConsumer {

    private final ObjectMapper objectMapper;
    private final ThreatService threatService;

    @KafkaListener(
            topics = "ai-result-topic",
            groupId = "ai-result-group",
            containerFactory = "kafkaListenerContainerFactory"
    )
    public void consume(String message){
        try{
            AiResponseDto aiResponse = objectMapper.readValue(message, AiResponseDto.class);
            threatService.saveAiDetectedThreat(aiResponse);
            log.info("AI analysis result received. logId={}",aiResponse.getLogId());
        }catch (JsonProcessingException exception){
            log.warn("Invalid AI result message. reason={}",exception.getOriginalMessage());
        }catch (Exception exception){
            log.error("Failed to save AI result",exception);
        }
    }
}