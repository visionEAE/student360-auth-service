package co.edu.icesi.student360.auth.infrastructure.config;

import co.edu.icesi.student360.auth.domain.port.AccessTokenIssuer;
import co.edu.icesi.student360.auth.domain.port.AppUserRepository;
import co.edu.icesi.student360.auth.domain.port.AuthSessionRepository;
import co.edu.icesi.student360.auth.domain.port.LoginAttemptLimiter;
import co.edu.icesi.student360.auth.domain.port.PasswordHasher;
import co.edu.icesi.student360.auth.domain.port.RefreshTokenRepository;
import co.edu.icesi.student360.auth.domain.port.SigningKeyProvider;
import co.edu.icesi.student360.auth.domain.service.AuthenticationService;
import co.edu.icesi.student360.auth.domain.service.RefreshTokenCodec;
import co.edu.icesi.student360.auth.infrastructure.security.BcryptPasswordHasher;
import co.edu.icesi.student360.auth.infrastructure.security.InMemoryLoginAttemptLimiter;
import co.edu.icesi.student360.auth.infrastructure.security.NimbusAccessTokenIssuer;
import co.edu.icesi.student360.auth.infrastructure.security.PemSigningKeyProvider;
import co.edu.icesi.student360.common.audit.AuditTrail;
import java.nio.file.Path;
import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Binds each port to its stage 1 adapter. Swapping an adapter happens here and only here. */
@Configuration
public class AuthConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public SigningKeyProvider signingKeyProvider(AuthProperties properties) {
    return new PemSigningKeyProvider(
        Path.of(properties.signingKey().privateKeyPath()), properties.signingKey().keyId());
  }

  @Bean
  public AccessTokenIssuer accessTokenIssuer(
      SigningKeyProvider keys, AuthProperties properties, Clock clock) {
    return new NimbusAccessTokenIssuer(
        keys,
        properties.issuer(),
        properties.audience(),
        properties.accessTokenTimeToLive(),
        clock);
  }

  @Bean
  public PasswordHasher passwordHasher() {
    return new BcryptPasswordHasher();
  }

  @Bean
  public LoginAttemptLimiter loginAttemptLimiter(AuthProperties properties, Clock clock) {
    return new InMemoryLoginAttemptLimiter(
        properties.loginRateLimit().maxAttempts(), properties.loginRateLimit().window(), clock);
  }

  @Bean
  public RefreshTokenCodec refreshTokenCodec() {
    return new RefreshTokenCodec();
  }

  @Bean
  public AuthenticationService authenticationService(
      AppUserRepository users,
      AuthSessionRepository sessions,
      RefreshTokenRepository refreshTokens,
      AccessTokenIssuer accessTokens,
      PasswordHasher passwords,
      LoginAttemptLimiter limiter,
      RefreshTokenCodec codec,
      AuditTrail audit,
      AuthProperties properties,
      Clock clock) {
    return new AuthenticationService(
        users,
        sessions,
        refreshTokens,
        accessTokens,
        passwords,
        limiter,
        codec,
        audit,
        clock,
        properties.refreshTokenTimeToLive());
  }
}
