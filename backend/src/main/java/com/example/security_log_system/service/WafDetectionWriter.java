package com.example.security_log_system.service;


import com.example.security_log_system.dto.WafDetectionEventDto;
import com.example.security_log_system.dto.WafMatchedRuleDto;
import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.entity.WafDetection;
import com.example.security_log_system.repository.ThreatRepository;
import com.example.security_log_system.repository.WafDetectionRepository;
import com.example.security_log_system.util.UtcDateTime;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

@Slf4j
@Service
public class WafDetectionWriter {

    private static final DateTimeFormatter EVENT_TIME_FORMAT =
                DateTimeFormatter.ofPattern(
                        "EEE MMM d HH:mm:ss uuuu",
                        Locale.ENGLISH
                ).withResolverStyle(ResolverStyle.STRICT);

    private final ThreatRepository threatRepository;
    private final WafDetectionRepository wafDetectionRepository;
    private final ObjectMapper objectMapper;
    private final ZoneId eventZone;
    private final RequestCorrelationService requestCorrelationService;
    private final RequestAlertService requestAlertService;
    private final AutoBlacklistPolicyService autoBlacklistPolicyService;

    public WafDetectionWriter(
            ThreatRepository threatRepository,
            WafDetectionRepository wafDetectionRepository,
            ObjectMapper objectMapper,
            RequestCorrelationService requestCorrelationService,
            RequestAlertService requestAlertService,
            AutoBlacklistPolicyService autoBlacklistPolicyService,
            @Value("${app.kafka.waf.event-zone:UTC}") String eventZone
    ){
        this.threatRepository = threatRepository;
        this.wafDetectionRepository = wafDetectionRepository;
        this.objectMapper = objectMapper;
        this.requestCorrelationService = requestCorrelationService;
        this.requestAlertService = requestAlertService;
        this.autoBlacklistPolicyService = autoBlacklistPolicyService;
        this.eventZone = ZoneId.of(eventZone);
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void saveNewDetection(WafDetectionEventDto event){
        LogEntry linkedLog =
                requestCorrelationService
                        .lockAndFindLog(event.getRequestId())
                        .orElse(null);

        // 잠금을 기다리는 동안 다른 처리가 저장했을 수도 있으므로 다시 확인한다
        if(wafDetectionRepository.existsByRequestId(event.getRequestId())){
            return;
        }

        LocalDateTime receivedAt = UtcDateTime.now();
        LocalDateTime occurredAt = parseOccurredAt(event.getTime());

        String rulesJson = serializeRules(event.getMatchedRules());
        String severity = determineSeverity(event.getMatchedRules());

        DetectedThreat threat = DetectedThreat.builder()
                // 공통 요청 ID로 연결할 수 있을 때까지 원본 로그는 NULL
                .logEntry(linkedLog)
                .threatType("WAF Detection")
                .severity(severity)
                .description("WAF 규칙 " +event.getMatchedRules().size() + "건 일치")
                .detectedAt(receivedAt)
                .isChecked(false)
                .build();

        DetectedThreat savedThreat = threatRepository.save(threat);

        WafDetection detection = WafDetection.builder()
                .requestId(event.getRequestId())
                .detectedThreat(savedThreat)
                .clientIp(event.getClientIp())
                .requestMethod(event.getMethod())
                .requestPath(event.getPath())
                .responseStatus(event.getStatus())
                .anomalyScore(event.getAnomalyScore())
                .matchedRulesJson(rulesJson)
                .eventTimeRaw(event.getTime())
                .occurredAt(occurredAt)
                .receivedAt(receivedAt)
                .build();

        // DB 제약 위반을 이 트랜잭션 안에서 확인한다.
        // 실패하면 위에서 저장한 DetectedThreat도 함께 롤백된다.
        wafDetectionRepository.saveAndFlush(detection);

        // 전송할 알림 상태 저장
        requestAlertService.recordWaf(
                event.getRequestId(),
                event.getClientIp(),
                severity
        );

        if(linkedLog != null){
            autoBlacklistPolicyService.evaluate(linkedLog);
        }
    }


    private String serializeRules(List<WafMatchedRuleDto> rules){

        try{
            return objectMapper.writeValueAsString(rules);
        }  catch (JsonProcessingException exception) {
            throw new IllegalStateException("WAF matched rules serialization failed.");
        }
    }

    private LocalDateTime parseOccurredAt(String rawTime){

        if(rawTime == null || rawTime.isBlank()){
            return null;
        }

        // 날짜의 한 자리 일자 앞에 공백이 두 개 있어도 처리
        String normalized = rawTime.trim().replaceAll("\\s+"," ");

        try{
            LocalDateTime localTime =
                    LocalDateTime.parse(normalized,EVENT_TIME_FORMAT);

            return localTime.atZone(eventZone)
                    .withZoneSameInstant(ZoneOffset.UTC)
                    .toLocalDateTime();

        } catch (DateTimeParseException exception){
            // 원문은 eventTimeRaw에 보존한다.
            // 현재 시각으로 대체해서 발생 시각을 왜곡하지 않는다.
            log.warn("WAF event time could not be parsed; "+ "raw time will be preserved.");
            return null;
        }
    }

    private String determineSeverity(List<WafMatchedRuleDto> rules){

        Integer highestSeverity = rules.stream()
                .map(WafMatchedRuleDto::getSeverity)
                .map(this::parseSeverity)
                .filter(Objects::nonNull)
                // ModSecurity에서는 작은 숫자가 더 심각하다.
                .min(Integer::compareTo)
                .orElse(null);

        if(highestSeverity == null){
            return "UNKNOWN";
        }

        if(highestSeverity <=2){
            return "CRITICAL";
        }
        if(highestSeverity == 3){
            return "HIGH";
        }

        if(highestSeverity == 4){
            return "MEDIUM";
        }

        return "LOW";
    }

    private Integer parseSeverity(String rawSeverity){

        if(rawSeverity ==null){
            return null;
        }

        String normalized = rawSeverity.trim().toUpperCase(Locale.ROOT);

        return switch (normalized){
            case "0" , "EMERGENCY" ->0;
            case "1" , "ALERT" ->1;
            case "2" , "CRITICAL" ->2;
            case "3" , "ERROR" ->3;
            case "4", "WARNING" -> 4;
            case "5" , "NOTICE" ->5;
            case "6" , "INFO" ->6;
            case "7" , "DEBUG" ->7;
            default -> null;
        };

    }


}
