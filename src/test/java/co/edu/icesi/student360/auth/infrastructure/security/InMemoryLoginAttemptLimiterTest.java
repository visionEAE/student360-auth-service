package co.edu.icesi.student360.auth.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.icesi.student360.common.api.exception.RateLimitExceededException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class InMemoryLoginAttemptLimiterTest {

  private final AtomicReference<Instant> now =
      new AtomicReference<>(Instant.parse("2026-08-30T10:00:00Z"));
  private final Clock clock =
      new Clock() {
        @Override
        public java.time.ZoneId getZone() {
          return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
          return this;
        }

        @Override
        public Instant instant() {
          return now.get();
        }
      };
  private final InMemoryLoginAttemptLimiter limiter =
      new InMemoryLoginAttemptLimiter(3, Duration.ofMinutes(1), clock);

  @Test
  void shouldBlockAfterMaxFailuresAndReleaseWhenWindowSlides() {
    limiter.recordFailure("key");
    limiter.recordFailure("key");
    limiter.recordFailure("key");

    assertThatThrownBy(() -> limiter.assertAllowed("key"))
        .isInstanceOf(RateLimitExceededException.class);

    now.set(now.get().plus(Duration.ofSeconds(61)));
    assertThatCode(() -> limiter.assertAllowed("key")).doesNotThrowAnyException();
  }

  @Test
  void shouldResetOnSuccess() {
    limiter.recordFailure("key");
    limiter.recordFailure("key");
    limiter.recordFailure("key");
    limiter.reset("key");

    assertThatCode(() -> limiter.assertAllowed("key")).doesNotThrowAnyException();
  }

  @Test
  void shouldKeepKeysIndependent() {
    limiter.recordFailure("a");
    limiter.recordFailure("a");
    limiter.recordFailure("a");

    assertThatCode(() -> limiter.assertAllowed("b")).doesNotThrowAnyException();
  }
}
