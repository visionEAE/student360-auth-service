package co.edu.icesi.student360.auth.domain.model;

import java.time.Instant;

public record IssuedAccessToken(String value, Instant expiresAt) {}
