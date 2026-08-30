package co.edu.icesi.student360.auth.domain.port;

/**
 * Port: throttles credential guessing. Stage 1 keeps counters in memory; a multi-instance
 * deployment would back it with a shared store, behind this same interface.
 */
public interface LoginAttemptLimiter {

  /**
   * @throws co.edu.icesi.student360.common.api.exception.RateLimitExceededException when the key
   *     has exhausted its attempts for the current window
   */
  void assertAllowed(String key);

  void recordFailure(String key);

  void reset(String key);
}
