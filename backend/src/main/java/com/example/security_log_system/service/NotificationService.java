package com.example.security_log_system.service;

import com.example.security_log_system.util.UtcDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    // 웹소켓 전송 도구
    private final SimpMessagingTemplate messagingTemplate;

    // WebSocket 알림 전송을 별도 스레드에서 처리
    @Async
    public void sendUrgentAlert(String ip, String type, int level){

        log.warn("Real-time threat alert sent. type={},level={}", type, level);

        // 리액트 대시보드로 데이터 전송
        Map<String,Object> payload = new HashMap<>();
        payload.put("ip",ip);
        payload.put("type",type);
        payload.put("level",level);
        payload.put("time", UtcDateTime.toOffset(UtcDateTime.now()));

        messagingTemplate.convertAndSend("/topic/threats",payload);
    }

}
