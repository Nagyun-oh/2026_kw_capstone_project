package com.example.security_log_system.security;


import jakarta.servlet.http.HttpSessionBindingEvent;
import jakarta.servlet.http.HttpSessionBindingListener;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// HTTP 세션 하나에 연결된 WebSocket들을 관리
/*
* HTTP 로그인 세션 하나
  ├─ 대시보드 탭 A의 WebSocket
  ├─ 대시보드 탭 B의 WebSocket
  └─ 대시보드 탭 C의 WebSocket
* */
@Slf4j
public class SessionWebSocketConnections implements HttpSessionBindingListener {

    // HTTP 세션과 WebSocket attributes에서 사용할 이름
    public static final String ATTRIBUTE_NAME =
            SessionWebSocketConnections.class.getName();

    // 1008: 정책 위반을 나타내는 WebSocket 종료 코드
    private static final CloseStatus SESSION_ENDED =
            new CloseStatus(1008,"HTTP session ended");

    private final Map<String, WebSocketSession> connections = new HashMap<>();

    // HTTP 세션이 끝난 뒤에는 새로운 연결 등록도 거부
    private boolean closed = false; // 관리 객체가 종료 상태인지 표시

    /*
    * synchronized는 여러 스레드가 공유 상태를 동시에 변경하지 못하도록 잠그는 것이다
    * 여기서는 connections와 closed를 보호함
    * */
    // 새 WebSocket 등록
    public synchronized boolean register(WebSocketSession session){

        if(closed || !session.isOpen()){
            return false;
        }

        connections.put(session.getId(),session);
        return true;
    }

    // 관리 목록에서 제거
    public synchronized void unregister(WebSocketSession session){
        connections.remove(session.getId());
    }

    // 세션 무효화·만료로 이 객체가 세션에서 제거되면 호출됨
    @Override
    public void valueUnbound(HttpSessionBindingEvent event){
        closeAll();
    }

    public void closeAll(){

        List<WebSocketSession> sessionToClose;

        // 이미 종료했다면 반환
        synchronized (this){
            if(closed){
                return;
            }

            // 새 등록 차단
            closed = true;

            // 종료할 연결들을 별도 리스트로 복사
            sessionToClose = List.copyOf(connections.values());

            // 관리 목록 비우기
            connections.clear();
        }

        // 실제 연결 종료는 잠금 밖에서 수행
        for (WebSocketSession session : sessionToClose){
            try{
                if(session.isOpen()){
                    session.close(SESSION_ENDED);
                }

            } catch (IOException | RuntimeException exception){
                // 하나의 종료가 실패해도 나머지 연결은 게속 종료
                log.warn(
                        "WebSocket 종료 실패: websocketId={}",
                        session.getId(),
                        exception
                );
            }
        }
    }
}
