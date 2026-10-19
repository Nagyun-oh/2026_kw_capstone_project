package com.example.security_log_system.exception;

// 다시 처리해도 해결되지 않는 WAF 메시지 형식·필수값 오류
// 이 예외를 따로 만드는 이유는 입력 오류와 DB 장애를 구분하기 위함.
/*
 - JSON 문법 오류 및 필수값 누락 -> 같은 메시지를 재시도해도 해결되지 않으므로 DLT로 전달
 - DB 연결 등 저장 처리 오류 -> 잠시 후 복구될 수 있으므로 재시도
 */
public class InvalidWafEventException extends RuntimeException{

    public InvalidWafEventException(String message){
        super(message);
    }
}
