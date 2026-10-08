package com.example.security_log_system.security;


import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.WebSocketHandlerDecorator;

// 기존 WebSocket 처리에 세션별 연결 등록·제거 기능을 추가
public class SessionWebSocketHandlerDecorator extends WebSocketHandlerDecorator {

    private static final CloseStatus SESSION_UNAVAILABLE =
            new CloseStatus(1008,"HTTP session unavailable");

    public SessionWebSocketHandlerDecorator(WebSocketHandler delegate){
        super(delegate);
    }

    // 연결이 열린 직후 처리
    @Override
    public void afterConnectionEstablished(WebSocketSession session)
        throws Exception{

        SessionWebSocketConnections connectionsManager =
                getConnectionsManager(session);

        // HTTP 세션의 관리 객체가 없는 연결을 허용하지 않음
        if(connectionsManager == null){
            session.close(SESSION_UNAVAILABLE);
            return;
        }

        try{
            // Spring의 기존 WebSocket 연결 초기화 수행
            super.afterConnectionEstablished(session);

            // 연결 준비 도중 세션이 종료됐다면 등록이 거부됨
            if(!connectionsManager.register(session)){
                session.close(SESSION_UNAVAILABLE);
            }
        } catch (Exception exception){
            // 연결 초기화가 실패하면 관리 목록에서도 제거
            connectionsManager.unregister(session);
            throw exception;
        }
    }

    // 연결이 닫힌 뒤 정리
    @Override
    public void afterConnectionClosed(
            WebSocketSession session,
            CloseStatus closeStatus
    ) throws Exception{

        SessionWebSocketConnections connectionsManager =
                getConnectionsManager(session);

        if(connectionsManager !=null){
            connectionsManager.unregister(session);
        }

        // Spring의 기존 연결 종료·구독 정리도 수행
        super.afterConnectionClosed(session,closeStatus);
    }

    // 앞의 핸드셰이크 인터셉트에서 저장한 객체를 WebSocket 세션의 attributes에서 꺼내기
    private SessionWebSocketConnections getConnectionsManager(WebSocketSession session){
        Object attribute = session.getAttributes().get(
                SessionWebSocketConnections.ATTRIBUTE_NAME
        );

        if(attribute instanceof SessionWebSocketConnections manager){
            return manager;
        }
        return null;
    }
}
