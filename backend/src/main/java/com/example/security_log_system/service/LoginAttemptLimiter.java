package com.example.security_log_system.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 관리자 로그인 실패 횟수를 사용자 이름별로 세어 일정 시간 잠근다(무차별 대입 완화).
 *
 * <p>클라이언트 IP는 기준으로 쓰지 않는다. 백엔드 앞에 호스트 Nginx와 프론트 Nginx가 있어 원격 주소는
 * 프록시 주소이고, 임의의 X-Forwarded-For는 신뢰하지 않는다(AGENTS.md). 대신 사용자 이름 기준이라
 * 공격자가 특정 계정을 잠글 수는 있으므로 잠금은 일정 시간 뒤 자동으로 풀린다.
 *
 * <p>백엔드 인스턴스 하나의 메모리에 둔다(현재 배포는 backend 1개). 재시작하면 기록이 사라진다.
 */
@Component
public class LoginAttemptLimiter {

    /** 추적하는 사용자 이름이 이보다 많아지면 만료된 기록부터 정리한다. */
    static final int CLEANUP_THRESHOLD = 10_000;

    private final int maxFailures;
    private final Duration window;
    private final Duration lockDuration;
    private final Clock clock;
    private final ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();

    @Autowired
    public LoginAttemptLimiter(
            @Value("${app.auth.login-limit.max-failures:5}") int maxFailures,
            @Value("${app.auth.login-limit.window-seconds:900}") long windowSeconds,
            @Value("${app.auth.login-limit.lock-seconds:900}") long lockSeconds
    ) {
        this(maxFailures, Duration.ofSeconds(windowSeconds), Duration.ofSeconds(lockSeconds), Clock.systemUTC());
    }

    LoginAttemptLimiter(int maxFailures, Duration window, Duration lockDuration, Clock clock) {
        if (maxFailures < 1 || window.isZero() || window.isNegative()
                || lockDuration.isZero() || lockDuration.isNegative()) {
            throw new IllegalArgumentException("login limit settings must be positive");
        }
        this.maxFailures = maxFailures;
        this.window = window;
        this.lockDuration = lockDuration;
        this.clock = clock;
    }

    /** 잠겨 있으면 풀릴 때까지 남은 초(올림), 아니면 0. */
    public long retryAfterSeconds(String username) {
        Attempt attempt = attempts.get(key(username));
        Instant now = clock.instant();
        if (attempt == null || attempt.lockedUntil() == null || !now.isBefore(attempt.lockedUntil())) {
            return 0;
        }
        long millis = Duration.between(now, attempt.lockedUntil()).toMillis();
        return Math.max(1, (millis + 999) / 1000);
    }

    /** 인증 실패를 기록한다. 기간 안에서 최대 횟수에 닿으면 잠근다. */
    public void recordFailure(String username) {
        Instant now = clock.instant();
        attempts.compute(key(username), (k, attempt) -> {
            Attempt current = attempt == null || expired(attempt, now) ? new Attempt(now, 0, null) : attempt;
            int failures = current.failures() + 1;
            Instant lockedUntil = failures >= maxFailures ? now.plus(lockDuration) : null;
            return new Attempt(current.windowStart(), failures, lockedUntil);
        });
        if (attempts.size() > CLEANUP_THRESHOLD) {
            attempts.entrySet().removeIf(entry -> expired(entry.getValue(), now));
        }
    }

    /** 로그인에 성공하면 그 사용자 이름의 실패 기록을 지운다. */
    public void recordSuccess(String username) {
        attempts.remove(key(username));
    }

    int trackedUsernames() {
        return attempts.size();
    }

    private boolean expired(Attempt attempt, Instant now) {
        if (attempt.lockedUntil() != null) {
            return !now.isBefore(attempt.lockedUntil());
        }
        return !now.isBefore(attempt.windowStart().plus(window));
    }

    private static String key(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    private record Attempt(Instant windowStart, int failures, Instant lockedUntil) {
    }
}
