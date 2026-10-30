package com.example.security_log_system.service;

import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.entity.WafDetection;
import com.example.security_log_system.repository.ThreatRepository;
import com.example.security_log_system.repository.WafDetectionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;


@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(propagation = Propagation.MANDATORY)
public class AutoBlacklistPolicyService {

    private final ThreatRepository threatRepository;
    private final WafDetectionRepository wafDetectionRepository;
    private final BlacklistService blacklistService;

    /*
    * 호출자는 같은 requestId의 잠금을 획득하고,
    * 새 탐지 기록을 저장한 뒤 호출해야 한다.
    * */
    public void evaluate(LogEntry logEntry){
        if(logEntry == null
            || logEntry.getId() == null
                || logEntry.getRequestId() == null
                || logEntry.getRequestId().isBlank()){
            return;
        }

        String clientIp = logEntry.getIpAddress();

        if(clientIp == null
                || clientIp.isBlank()
                ||"0.0.0.0".equals(clientIp)){
            return;
        }

        WafDetection wafDetection = wafDetectionRepository
                .findByRequestId(logEntry.getRequestId())
                .orElse(null);

        if(wafDetection == null){
            return;
        }

        /*
        * 같은 요청인데 원본 로그와 WAF의 IP가 다르면
        * 자동 차단 대상을 임의로 선택하지 않는다.
        * */
        if(!clientIp.equals(wafDetection.getClientIp())){
            log.warn("Automatic blacklist registration skipped: "
            +"client IP mismatch. requestId={}", logEntry.getRequestId());
            return;
        }

        DetectedThreat aiThreat = threatRepository
                .findByLogEntry_IdAndThreatType(
                        logEntry.getId(),
                        "AI Detection"
                )
                .orElse(null);

        if(aiThreat == null){
            return;
        }

        DetectedThreat wafThreat = wafDetection.getDetectedThreat();

        DetectedThreat sourceThreat =
                wafThreat.getId() < aiThreat.getId()
                        ? wafThreat : aiThreat;

        String reason =
                "[자동] 동일 요청에서 WAF·AI 모두 탐지"
                +" (WAF 위협 #"
                + wafThreat.getId()
                + ", AI 위협 #"
                + aiThreat.getId()
                +")";

        blacklistService.addToBlacklist(
                clientIp,
                reason,
                4,
                sourceThreat
        );
    }
}
