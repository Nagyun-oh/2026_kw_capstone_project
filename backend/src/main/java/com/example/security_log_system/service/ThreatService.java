package com.example.security_log_system.service;

import com.example.security_log_system.dto.*;
import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.repository.LogRepository;
import com.example.security_log_system.repository.ThreatRepository;
import com.example.security_log_system.repository.ThreatSpecification;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import com.example.security_log_system.util.UtcDateTime;
import com.example.security_log_system.dto.GroupedThreatResponseDto;
import com.example.security_log_system.exception.AiLogNotReadyException;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class ThreatService {

    private final LogRepository logRepository;
    private final ThreatRepository threatRepository;
    private final AutoBlacklistPolicyService autoBlacklistPolicyService;
    private final NotificationService notificationService;
    private final MeterRegistry meterRegistry;
    private final RequestCorrelationService requestCorrelationService;
    private final RequestAlertService requestAlertService;
    private final PipelineTrace pipelineTrace;

    @Transactional(readOnly = true)
    public Page<ThreatResponseDto> getThreats(ThreatSearchCondition condition, Pageable pageable){
        return threatRepository.findAll(ThreatSpecification.search(condition),pageable)
                .map(ThreatResponseDto::from);
    }


    // HTTP 보조 API를 통해 전달된 위협 저장
    public void saveDetectedThreat(ThreatDto threatDto) {

        DetectedThreat threat = DetectedThreat.builder()
                .threatType(threatDto.getThreatType())
                .severity(mapRiskLevelToSeverity(threatDto.getDangerLevel()))
                .description(threatDto.getDescription())
                .detectedAt(UtcDateTime.now())
                .build();

        DetectedThreat savedThreat = threatRepository.save(threat);

        incrementThreatDetectedMetric(threat.getSeverity());

        log.info("Threat recorded through HTTP endpoint. type={},severity={}",
                threat.getThreatType(),
                threat.getSeverity()
        );

        // 위험도가 높으면 자동으로 블랙리스트 등록
        if (threatDto.getDangerLevel() >= 4) {
            notificationService.sendUrgentAlert(threatDto.getClientIp(),"[API 수동 테스트]",threatDto.getDangerLevel());
        }
    }

    // Kafka AI 분석 결과를 기반으로 위협 저장
    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void saveAiDetectedThreat(AiResponseDto aiResponse) {

        // 롤백 → 커밋 성공 기록 없음
        if (aiResponse.getLogId() ==null){
            throw new IllegalArgumentException("AI response logId is null");
        }

        LogEntry entry = logRepository.findById(aiResponse.getLogId())
                .orElseThrow(() -> new AiLogNotReadyException(
                        aiResponse.getLogId()
                ));

        // 정상 결과 → AI_RESULT_COMMITTED / NORMAL
        if ("0.0.0.0".equals(aiResponse.getIpAddress())) {
            pipelineTrace.afterCommit(
                    "AI_RESULT_COMMITTED",
                    "NORMAL",
                    entry.getRequestId(),
                    entry.getId(),
                    null
            );
            return;
        }

        requestCorrelationService.lockForAiResult(entry);

        // 중복 결과 → AI_RESULT_DUPLICATE / SKIPPED
        if(threatRepository.existsByLogEntry_IdAndThreatType(
                entry.getId(),
                "AI Detection"
        ))
        {
            pipelineTrace.afterCommit(
                    "AI_RESULT_DUPLICATE",
                    "SKIPPED",
                    entry.getRequestId(),
                    entry.getId(),
                    null
            );
            return;
        }

        String severity =
                aiResponse.getThreatScore() >= 0.8
                    ? "CRITICAL" : "HIGH";

        DetectedThreat threat = DetectedThreat.builder()
                .logEntry(entry)
                .threatType("AI Detection")
                .severity(severity)
                .description(aiResponse.getReason())
                .detectedAt(UtcDateTime.now())
                .build();

        DetectedThreat savedThreat = threatRepository.save(threat);

        incrementThreatDetectedMetric(threat.getSeverity());

        requestAlertService.recordAi(
                entry.getRequestId(),
                entry.getId(),
                entry.getIpAddress(),
                severity
        );

        autoBlacklistPolicyService.evaluate(entry);

        // 위협 결과 → AI_RESULT_COMMITTED / DETECTED
        pipelineTrace.afterCommit(
                "AI_RESULT_COMMITTED",
                "DETECTED",
                entry.getRequestId(),
                entry.getId(),
                savedThreat.getId()
        );

    }

    @Transactional(readOnly = true)
    public Page<GroupedThreatResponseDto> getGroupedThreats(
            ThreatSearchCondition condition,
            Pageable pageable
    ){
        String source = StringUtils.hasText(condition.getSource())
                ? condition.getSource()
                : null;

        String severity = StringUtils.hasText(condition.getSeverity())
                ? condition.getSeverity().trim().toUpperCase(Locale.ROOT)
                : null;

        String threatType = StringUtils.hasText(condition.getThreatType())
                ? condition.getThreatType().trim()
                : null;

        return threatRepository.findGroupedThreats(
                source,
                severity,
                threatType,
                condition.getThreatId(),
                pageable
        ).map(this::toGroupedThreatResponse);
    }

    private GroupedThreatResponseDto toGroupedThreatResponse(
            ThreatRepository.GroupedThreatRow row
    ){
        Long wafId = row.getWafThreatId();
        Long aiId = row.getAiThreatId();

        List<String> types = new ArrayList<>();

        if(wafId !=null && aiId !=null){
            if(wafId < aiId){
                types.add("WAF Detection");
                types.add("AI Detection");
            } else {
                types.add("AI Detection");
                types.add("WAF Detection");
            }
        } else if(wafId !=null){
            types.add("WAF Detection");
        }else if(aiId !=null){
            types.add("AI Detection");
        }else {
            types.add(row.getFallbackType() !=null
            ? row.getFallbackType()
            : "UNKNOWN");
        }

        String severity = switch(row.getSeverityRank()){
            case 4 -> "CRITICAL";
            case 3 -> "HIGH";
            case 2 -> "MEDIUM";
            case 1 -> "LOW";
            default -> "UNKNOWN";
        };

        return GroupedThreatResponseDto.builder()
                .id(row.getId())
                .logId(row.getLogId())
                .wafThreatId(wafId)
                .aiThreatId(aiId)
                .threatTypes(List.copyOf(types))
                .severity(severity)
                .wafDescription(row.getWafDescription())
                .aiDescription(row.getAiDescription())
                .otherDescription(
                        wafId ==null && aiId == null
                        ? row.getFallbackDescription() : null
                )
                .build();
    }

    private void incrementThreatDetectedMetric(String severity){
        Counter.builder("security.threats.detected")
                .description("Number of detected security threats")
                .tag("severity",severity)
                .register(meterRegistry)
                .increment();
    }

    // 위험도 숫자를 (1~5) 를 "HIGH", "CRITICAL" 등의 문자열로 바꿔주는 편의 메서드
    private String mapRiskLevelToSeverity(int level) {
        if (level >= 4) return "CRITICAL";
        if (level >= 3) return "HIGH";
        return "MEDIUM";
    }

}

