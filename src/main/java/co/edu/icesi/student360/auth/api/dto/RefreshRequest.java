package co.edu.icesi.student360.auth.api.dto;

import jakarta.validation.constraints.Size;

/** Optional body: browser clients send the refresh token as a cookie instead. */
public record RefreshRequest(@Size(max = 128) String refreshToken) {}
