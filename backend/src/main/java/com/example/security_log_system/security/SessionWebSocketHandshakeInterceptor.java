package com.example.security_log_system.security;


import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.util.Map;

// WebSocket 연결 준비 단계에서 HTTP 세션의 연결 관리 객체를 전달
// WebSocket은 처음에 HTTP 요청으로 연결을 요청하고, 핸드셰이크를 통해 WebSocket 연결로 전환함
public class SessionWebSocketHandshakeInterceptor implements HandshakeInterceptor {

    // 연결 전 검사와 속성 전달
    @Override
    public boolean beforeHandshake(
            ServerHttpRequest request,
            ServerHttpResponse response,
            WebSocketHandler wsHandler,
            Map<String,Object> attributes
    ){

        // HTTP 세션에 접근할 수 있는 요청인지 확인
        if(!(request instanceof ServletServerHttpRequest serverHttpRequest)){
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return false;
        }

        // 인증된 사용자인지 확인
        // 관리자 권한 검사는 기존 Spring Security 설정에서 수행
        if(request.getPrincipal() ==null){
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;
        }

        // 기존 로그인 세션만 사용하고 새 세션은 생성하지 않음
        HttpSession httpSession =
                serverHttpRequest.getServletRequest().getSession(false);

        if(httpSession == null){
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;
        }

        try{
            SessionWebSocketConnections connectionManager;

            // 같은 세션에서 여러 탭이 동시에 연결해도 관리 객체는 하나만 생성
            synchronized (httpSession){
                connectionManager =
                        (SessionWebSocketConnections) httpSession.getAttribute(
                                SessionWebSocketConnections.ATTRIBUTE_NAME
                        );

                if(connectionManager == null){
                    connectionManager = new SessionWebSocketConnections();

                    httpSession.setAttribute(
                            SessionWebSocketConnections.ATTRIBUTE_NAME,
                            connectionManager
                    );
                }
            }

            // WebSocket 쪽에서도 같은 관리 객체에 접근하도록 전달
            attributes.put(
                    SessionWebSocketConnections.ATTRIBUTE_NAME,
                    connectionManager
            );
            return true;

        } catch (IllegalStateException exception){
            // 연결을 준비하는 도중 로그아웃되는 상황 처리
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;
        }
    }

    // 핸드셰이크 처리 후 후속 작업
    @Override
    public void afterHandshake(
            ServerHttpRequest request,
            ServerHttpResponse response,
            WebSocketHandler wsHandler,
            Exception exception
    ){
        // 별도 후처리 없음.
        // 실제 연결 등록·제거는 SessionWebSocketHandlerDecorator에서 처리.
    }

}
