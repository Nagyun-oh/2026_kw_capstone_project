package com.example.security_log_system.service;

import com.example.security_log_system.dto.RequestAlertMessage;
import com.example.security_log_system.repository.RequestAlertRepository;
import com.example.security_log_system.repository.RequestAlertRepository.AlertState;
import com.example.security_log_system.util.UtcDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

// 커밋된 알림을 WebSocket으로 보내는 클래스
@Service
@RequiredArgsConstructor
public class RequestAlertPublisher {

    private final RequestAlertRepository requestAlertRepository;
    private final SimpMessagingTemplate messagingTemplate;

    @Transactional
    public void publish(String alertKey){
        AlertState state = requestAlertRepository
                .findForUpdate(alertKey)
                .orElse(null);

        if(state == null || !state.pending()){
            return;
        }

        List<String> sources = new ArrayList<>();

        if(state.wafDetected()){
            sources.add("WAF");
        }
        if(state.aiDetected()){
            sources.add("AI");
        }

        String eventType =
                state.publishedRevision() == 0
                ? "CREATED" : "UPDATED";

        String type = String.join(" + ",sources) +" Detection";

        RequestAlertMessage message = new RequestAlertMessage(
                state.alertId(),
                eventType,
                state.revision(),
                state.clientIp(),
                type,
                state.alertLevel(),
                UtcDateTime.toOffset(state.updatedAt()),
                List.copyOf(sources)
        );

        messagingTemplate.convertAndSend("/topic/threats",message);

        // 전송 호출이 예외 없이 끝난 뒤에만 처리 완료로 기록한다.
        requestAlertRepository.markPublished(
                state.alertKey(),
                state.revision()
        );
    }


}
