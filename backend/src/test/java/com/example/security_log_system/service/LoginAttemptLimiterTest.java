package com.example.security_log_system.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LoginAttemptLimiterTest {

    /** 테스트에서 시간을 직접 옮기는 시계 */
    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-11-08T00:00:00Z");

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private final MutableClock clock = new MutableClock();
    private final LoginAttemptLimiter limiter =
            new LoginAttemptLimiter(5, Duration.ofMinutes(15), Duration.ofMinutes(15), clock);

    private void fail(String username, int times) {
        for (int i = 0; i < times; i++) {
            limiter.recordFailure(username);
        }
    }

    @Test
    @DisplayName("기간 안에 최대 횟수만큼 실패하면 잠그고 남은 시간을 초 단위로 알려준다")
    void locksAfterMaxFailures() {
        fail("admin", 4);
        assertThat(limiter.retryAfterSeconds("admin")).isZero();

        fail("admin", 1);
        assertThat(limiter.retryAfterSeconds("admin")).isEqualTo(900);

        clock.advance(Duration.ofSeconds(100).plusMillis(1));
        assertThat(limiter.retryAfterSeconds("admin")).isEqualTo(800);
    }

    @Test
    @DisplayName("잠금 시간이 지나면 풀리고 실패 횟수를 처음부터 다시 센다")
    void unlocksAfterLockDurationAndStartsOver() {
        fail("admin", 5);
        clock.advance(Duration.ofMinutes(15));

        assertThat(limiter.retryAfterSeconds("admin")).isZero();
        fail("admin", 4);
        assertThat(limiter.retryAfterSeconds("admin")).isZero();
    }

    @Test
    @DisplayName("기간이 지난 실패는 세지 않는다")
    void failuresOutsideWindowDoNotAccumulate() {
        fail("admin", 4);
        clock.advance(Duration.ofMinutes(15));

        fail("admin", 4);
        assertThat(limiter.retryAfterSeconds("admin")).isZero();
    }

    @Test
    @DisplayName("성공하면 실패 기록을 지우고, 사용자 이름은 대소문자·앞뒤 공백을 구분하지 않는다")
    void successResetsAndKeysAreNormalized() {
        fail(" Admin ", 4);
        limiter.recordSuccess("admin");
        fail("ADMIN", 4);
        assertThat(limiter.retryAfterSeconds("admin")).isZero();

        fail("admin", 1);
        assertThat(limiter.retryAfterSeconds("Admin")).isEqualTo(900);
        assertThat(limiter.retryAfterSeconds("other")).isZero();
    }

    @Test
    @DisplayName("추적하는 사용자 이름이 많아지면 만료된 기록을 정리한다")
    void cleansUpExpiredEntries() {
        for (int i = 0; i <= LoginAttemptLimiter.CLEANUP_THRESHOLD; i++) {
            limiter.recordFailure("user-" + i);
        }
        clock.advance(Duration.ofMinutes(16));

        limiter.recordFailure("fresh");

        assertThat(limiter.trackedUsernames()).isEqualTo(1);
    }

    @Test
    @DisplayName("설정값은 양수여야 한다")
    void rejectsNonPositiveSettings() {
        assertThatThrownBy(() -> new LoginAttemptLimiter(0, Duration.ofMinutes(1), Duration.ofMinutes(1), clock))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginAttemptLimiter(1, Duration.ZERO, Duration.ofMinutes(1), clock))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
