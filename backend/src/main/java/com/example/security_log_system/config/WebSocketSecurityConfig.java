package com.example.security_log_system.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;

// 누가 연결하고 어떤 주소를 구독할 수 있는지 설정
@Configuration
@EnableWebSocketSecurity
public class WebSocketSecurityConfig {

    @Bean
    public AuthorizationManager<Message<?>>  messageAuthorizationManager(
            MessageMatcherDelegatingAuthorizationManager.Builder messages
    ){
        messages
                // 관리자만 STOMP 연결 허용
                .simpTypeMatchers(SimpMessageType.CONNECT)
                .hasRole("ADMIN")

                // 관리자만 위협 알림 구독 허용
                .simpSubscribeDestMatchers("/topic/threats")
                .hasRole("ADMIN")

                // 연결 유지·구독 해제·종료에 필요한 메시지
                .simpTypeMatchers(
                        SimpMessageType.HEARTBEAT,
                        SimpMessageType.UNSUBSCRIBE,
                        SimpMessageType.DISCONNECT
                ).hasRole("ADMIN")

                // 그 외 구독과 클라이언트의 메시지 발행은 차단
                .anyMessage()
                .denyAll();

        return messages.build();
    }
}
