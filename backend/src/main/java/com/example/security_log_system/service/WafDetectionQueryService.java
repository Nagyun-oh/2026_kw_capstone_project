package com.example.security_log_system.service;


import com.example.security_log_system.dto.WafDetectionDetailDto;
import com.example.security_log_system.dto.WafMatchedRuleDto;
import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.WafDetection;
import com.example.security_log_system.repository.WafDetectionRepository;
import com.example.security_log_system.util.UtcDateTime;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

// WAF 상세 조회 서비스
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class WafDetectionQueryService {

    private final WafDetectionRepository wafDetectionRepository;
    private final ObjectMapper objectMapper;

    public Optional<WafDetectionDetailDto> getDetail(Long threatId){
        return wafDetectionRepository.findByDetectedThreat_Id(threatId)
                .filter(detection ->
                        "WAF Detection".equals(
                                detection.getDetectedThreat().getThreatType()
                        )
                )
                .map(this::toResponse);
    }


    private WafDetectionDetailDto toResponse(WafDetection detection){
        DetectedThreat threat = detection.getDetectedThreat();

        Long logId = threat.getLogEntry() == null
                ? null
                : threat.getLogEntry().getId();

        return new WafDetectionDetailDto(
                detection.getId(),
                threat.getId(),
                logId,
                detection.getRequestId(),
                threat.getThreatType(),
                threat.getSeverity(),
                threat.getDescription(),
                detection.getClientIp(),
                detection.getRequestMethod(),
                detection.getRequestPath(),
                detection.getResponseStatus(),
                detection.getAnomalyScore(),
                detection.getEventTimeRaw(),
                UtcDateTime.toOffset(detection.getOccurredAt()),
                UtcDateTime.toOffset(detection.getReceivedAt()),
                readRules(detection.getMatchedRulesJson())
        );
    }

    private List<WafDetectionDetailDto.Rule> readRules(String json){

        if(json == null || json.isBlank()){
            throw new IllegalStateException(
                    "Stored WAF rules are missing"
            );
        }

        try{
            List<WafMatchedRuleDto> rules = objectMapper.readValue(
                    json,
                    new TypeReference<List<WafMatchedRuleDto>>(){}
            );

            if(rules == null
                || rules.isEmpty()
                || rules.stream().anyMatch(Objects::isNull)
            ){
                throw new IllegalStateException(
                        "Stored WAF rules are invalid."
                );
            }

            return rules.stream()
                    .map(rule -> new WafDetectionDetailDto.Rule(
                            rule.getId(),
                            rule.getMessage(),
                            rule.getSeverity(),
                            rule.getMatchedVariable(),
                            rule.getAttackTypes()
                    ))
                    .toList();

        } catch (JsonProcessingException exception){
            // 손상된 저장 데이터를 정상적인 빈 규칙 목록으로 숨기지 않는다.
            throw new IllegalStateException(
                    "Stored WAF rules could not be read."
            );
        }

    }

}
