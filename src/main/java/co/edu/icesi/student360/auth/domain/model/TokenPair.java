package co.edu.icesi.student360.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

/** What a successful login or refresh hands back. The refresh value appears here once, in clear. */
public record TokenPair(
    String accessToken,
    Instant accessTokenExpiresAt,
    String refreshToken,
    Instant refreshTokenExpiresAt,
    UUID sessionId) {}
