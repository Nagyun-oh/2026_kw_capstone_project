package com.example.security_log_system.exception;

/** 로그인 실패가 반복돼 사용자 이름이 잠겨 있을 때 던진다. 컨트롤러가 429와 Retry-After로 바꾼다. */
public class LoginRateLimitedException extends RuntimeException {

    private final long retryAfterSeconds;

    public LoginRateLimitedException(long retryAfterSeconds) {
        super("LOGIN_TEMPORARILY_LOCKED");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
