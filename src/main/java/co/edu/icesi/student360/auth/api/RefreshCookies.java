package co.edu.icesi.student360.auth.api;

import co.edu.icesi.student360.auth.infrastructure.config.AuthProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * The refresh token travels to browsers as an HttpOnly cookie scoped to the auth paths, so a script
 * injected into the SPA cannot read it. SameSite is configuration: Strict locally, None in
 * production, where the SPA and the gateway live on different run.app sites.
 */
@Component
public class RefreshCookies {

  private final AuthProperties.RefreshCookie settings;

  public RefreshCookies(AuthProperties properties) {
    this.settings = properties.refreshCookie();
  }

  public ResponseCookie issue(String refreshToken, Instant expiresAt, Instant now) {
    return builder(refreshToken).maxAge(Duration.between(now, expiresAt)).build();
  }

  public ResponseCookie clear() {
    return builder("").maxAge(Duration.ZERO).build();
  }

  public Optional<String> read(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return Optional.empty();
    }
    return Arrays.stream(cookies)
        .filter(cookie -> settings.name().equals(cookie.getName()))
        .map(Cookie::getValue)
        .filter(value -> !value.isBlank())
        .findFirst();
  }

  private ResponseCookie.ResponseCookieBuilder builder(String value) {
    return ResponseCookie.from(settings.name(), value)
        .httpOnly(true)
        .secure(settings.secure())
        .sameSite(settings.sameSite())
        .path(settings.path());
  }
}
