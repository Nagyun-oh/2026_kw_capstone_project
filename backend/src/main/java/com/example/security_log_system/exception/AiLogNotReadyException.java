package com.example.security_log_system.exception;


// 재시도할 수 있는 업무 오류
public class AiLogNotReadyException extends RuntimeException {

    public AiLogNotReadyException(long logId) {
        super("LogEntry not ready. logId=" + logId);
    }
}