package co.edu.icesi.student360.auth.api.dto;

import co.edu.icesi.student360.auth.domain.model.TokenPair;
import java.time.Duration;
import java.time.Instant;

public record TokenResponse(
    String accessToken,
    String tokenType,
    long expiresIn,
    String refreshToken,
    Instant refreshTokenExpiresAt,
    String sessionId) {

  public static TokenResponse from(TokenPair pair, Instant now) {
    return new TokenResponse(
        pair.accessToken(),
        "Bearer",
        Duration.between(now, pair.accessTokenExpiresAt()).toSeconds(),
        pair.refreshToken(),
        pair.refreshTokenExpiresAt(),
        pair.sessionId().toString());
  }
}
