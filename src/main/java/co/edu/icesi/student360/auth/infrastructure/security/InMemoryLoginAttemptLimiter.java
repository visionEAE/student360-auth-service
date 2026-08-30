package co.edu.icesi.student360.auth.infrastructure.security;

import co.edu.icesi.student360.auth.domain.port.LoginAttemptLimiter;
import co.edu.icesi.student360.common.api.exception.RateLimitExceededException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding-window counter of failed attempts per key (e-mail + source ip). Enough to make brute
 * force impractical for a single instance; a shared store replaces it behind the same port when
 * there is more than one.
 */
public class InMemoryLoginAttemptLimiter implements LoginAttemptLimiter {

  private final int maxAttempts;
  private final Duration window;
  private final Clock clock;
  private final Map<String, Deque<Instant>> failures = new ConcurrentHashMap<>();

  public InMemoryLoginAttemptLimiter(int maxAttempts, Duration window, Clock clock) {
    this.maxAttempts = maxAttempts;
    this.window = window;
    this.clock = clock;
  }

  @Override
  public void assertAllowed(String key) {
    Deque<Instant> attempts = failures.get(key);
    if (attempts == null) {
      return;
    }
    synchronized (attempts) {
      Instant now = clock.instant();
      evictOlderThanWindow(attempts, now);
      if (attempts.size() >= maxAttempts) {
        Duration retryAfter = Duration.between(now, attempts.peekFirst().plus(window));
        throw new RateLimitExceededException(retryAfter.isNegative() ? Duration.ZERO : retryAfter);
      }
    }
  }

  @Override
  public void recordFailure(String key) {
    Deque<Instant> attempts = failures.computeIfAbsent(key, ignored -> new ArrayDeque<>());
    synchronized (attempts) {
      Instant now = clock.instant();
      evictOlderThanWindow(attempts, now);
      attempts.addLast(now);
    }
  }

  @Override
  public void reset(String key) {
    failures.remove(key);
  }

  private void evictOlderThanWindow(Deque<Instant> attempts, Instant now) {
    Instant threshold = now.minus(window);
    while (!attempts.isEmpty() && attempts.peekFirst().isBefore(threshold)) {
      attempts.pollFirst();
    }
  }
}
