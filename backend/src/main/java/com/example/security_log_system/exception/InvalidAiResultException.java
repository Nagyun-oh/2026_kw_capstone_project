package com.example.security_log_system.exception;

// 입력 오류
public class InvalidAiResultException extends  RuntimeException{

    public InvalidAiResultException(String code){
        super(code);
    }
}
