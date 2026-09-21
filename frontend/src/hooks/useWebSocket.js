import { useState, useEffect, useRef } from 'react';
import SockJS from 'sockjs-client';
import {Client,ReconnectionTimeMode } from '@stomp/stompjs';
import { toast } from 'react-toastify';
import {WS_URL} from '../config';

function useWebSocket(onThreatReceived) {
  // 새로운 위협이 들어왔을 때 테이블 테두리 강조
  const [isNewThreat, setIsNewThreat] = useState(false);

  // WebSocket 연결 상태
  const [connectionStatus, setConnectionStatus] = useState("connecting");

  // App에서 전달한 최신 콜백 함수를 보관
  const callbackRef = useRef(onThreatReceived);

  // 강조 효과 해제를 위한 타이머 보관
  const highlightTimerRef = useRef(null);

  // App이 다시 렌더링되면 최신 콜백으로 교체
  useEffect( ()=>{
    callbackRef.current = onThreatReceived;
  }, [onThreatReceived]);


  useEffect(() => {
    
    const stompClient = new Client({
      // SockJS를 사용해 백엔드 WebSocket endpoint에 연결
      webSocketFactory: () => new SockJS(WS_URL),

      // 재연결 로직을 지수적으로 증가시킨다. (지수 백오프)
      reconnectTimeMode: ReconnectionTimeMode.EXPONENTIAL,

      // 최초 재연결은 1초후
      reconnectDelay: 1000,

      // 재연결 대기시간은 최대 30초
      maxReconnectDelay: 30000,

      // 재연결당 10초 안에 연결되지 않으면 연결 실패로 처리
      connectionTimeout: 10000,

      // 연결 상태 확인용 heartbeat
      heartbeatIncoming: 10000,
      heartbeatOutgoing: 10000,
      
      // STOMP 연결 성공시 실행
      onConnect: frame => {
        console.log("WebSocket connected", frame);
        setConnectionStatus("connected");

        // 백엔드의 위협 알림 topic 구독
        stompClient.subscribe("/topic/threats",
          sdkEvent => {
              // WebSocket 문자열을 JavaScript 객체로 변환
              const message = JSON.parse(sdkEvent.body);

              console.log("🚨 실시간 위협 알림 수신!",message);

              // 동일한 알림이 중복 표시되지 않도록 ID 생성
              const toastId = `threat-${message.ip}-${message.time}`;

              if (!toast.isActive(toastId)) {
                toast.error(`위협 감지! [${message.type}] IP: ${message.ip}`,
                   {
                    toastId: toastId,
                    position: "top-right",
                    autoClose: 5000,
                  }
              );
            }

            // App에서 전달한 최신 콜백 실행
            callbackRef.current?.(message);

            // 위협 테이블 강조
            setIsNewThreat(true);

            // 기존 타이머가 있다면 제거
            if(highlightTimerRef.current){
              clearTimeout(highlightTimerRef.current);
            }
            // 2초 후 강조 효과 해제
            highlightTimerRef.current = setTimeout( () =>{
              setIsNewThreat(false);
            }, 2000);
          }
        );
      },
      // > WebSocket 연결 자체가 실패한 경우
      onWebSocketError: error => {
        console.error("WebSocket connection failed",error);
        setConnectionStatus("reconnecting");
      },
      // > WebSocket 연결이 종료된 경우
      onWebSocketClose: event => {
        console.warn("WebSocket connection closed",event);
        setConnectionStatus("reconnecting");
      },
      // > STOMP Broker에서 오류 응답을 보낸 경우
      onStompError: frame => {
        console.error("STOMP broker error",frame.headers.message,frame.body);
        setConnectionStatus("error");
      },
    });

    setConnectionStatus("connecting");
    // WebSocket 연결 시작
    stompClient.activate();

    return () => {
      if(highlightTimerRef.current){
        clearTimeout(highlightTimerRef.current);
      }
      stompClient.deactivate();
    };
  },[]);

  return {
    isNewThreat,
    connectionStatus,
  };
}
    
export default useWebSocket;