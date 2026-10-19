package com.example.security_log_system.service;

import com.example.security_log_system.repository.RequestAlertRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

// WAF·AI 탐지를 같은 알림 기록으로 합치는 서비스 추가
@Service
@RequiredArgsConstructor
@Transactional(propagation = Propagation.MANDATORY)
public class RequestAlertService {

    private final RequestAlertRepository requestAlertRepository;

    public void recordWaf(String requestId,String clientIp,String severity){
        record(
                createKey(requestId,null),
                clientIp,
                true,
                severity
        );
    }

    public void recordAi(String requestId,Long logId,String clientIp, String severity){
        record(
                createKey(requestId,logId),
                clientIp,
                false,
                severity
        );
    }

    private void record(String alertKey,String clientIp, boolean waf,String severity){

        requestAlertRepository.createIfAbsent(alertKey,clientIp);

        RequestAlertRepository.AlertState current = requestAlertRepository
                .findForUpdate(alertKey)
                .orElseThrow(() -> new IllegalStateException(
                        "Request alert not found after insertion."
                ));

        boolean wafDetected = current.wafDetected() || waf;
        boolean aiDetected = current.aiDetected() || !waf;

        int alertLevel = Math.max(current.alertLevel(),toLevel(severity));

        boolean unchanged =
                wafDetected == current.wafDetected()
                && aiDetected == current.aiDetected()
                && alertLevel == current.alertLevel();

        if(unchanged) {
            return;
        }

        requestAlertRepository.updateDetection(
                alertKey,
                wafDetected,
                aiDetected,
                alertLevel
        );

    }

    private String createKey(String requestId, Long logId){
        if(requestId !=null){
            if(requestId.isBlank() || requestId.length() > 255){
                throw new IllegalArgumentException("Invalid request ID.");
            }
            return "request:"+requestId;
        }
        if(logId ==null){
            throw new IllegalArgumentException("Either requestId or logId is required.");
        }
        return "log:"+logId;
    }

    private int toLevel(String severity){
        if(severity == null){
            return 0;
        }
        return switch(severity){
            case "CRITICAL" ->4;
            case "HIGH" ->3;
            case "MEDIUM"->2;
            case "LOW"->1;
            default -> 0;
        };
    }

}
