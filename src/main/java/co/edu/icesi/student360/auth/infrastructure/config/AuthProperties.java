package co.edu.icesi.student360.auth.infrastructure.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
    @NotBlank String issuer,
    @NotBlank String audience,
    @NotNull SigningKey signingKey,
    @DefaultValue("PT15M") Duration accessTokenTimeToLive,
    @DefaultValue("P7D") Duration refreshTokenTimeToLive,
    @DefaultValue RefreshCookie refreshCookie,
    @DefaultValue LoginRateLimit loginRateLimit) {

  /** Kept as a string: Spring's Path conversion treats relative values as resource paths. */
  public record SigningKey(@NotBlank String privateKeyPath, @NotBlank String keyId) {}

  public record RefreshCookie(
      @DefaultValue("refresh_token") String name,
      @DefaultValue("true") boolean secure,
      @DefaultValue("/api/auth") String path) {}

  public record LoginRateLimit(
      @DefaultValue("5") int maxAttempts, @DefaultValue("PT1M") Duration window) {}
}
