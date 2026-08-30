package co.edu.icesi.student360.auth.domain.service;

import co.edu.icesi.student360.auth.domain.model.AccessTokenClaims;
import co.edu.icesi.student360.auth.domain.model.AppUser;
import co.edu.icesi.student360.auth.domain.model.AuthSession;
import co.edu.icesi.student360.auth.domain.model.IssuedAccessToken;
import co.edu.icesi.student360.auth.domain.model.RefreshToken;
import co.edu.icesi.student360.auth.domain.model.RevocationReason;
import co.edu.icesi.student360.auth.domain.model.TokenPair;
import co.edu.icesi.student360.auth.domain.model.UserProfile;
import co.edu.icesi.student360.auth.domain.port.AccessTokenIssuer;
import co.edu.icesi.student360.auth.domain.port.AppUserRepository;
import co.edu.icesi.student360.auth.domain.port.AuthSessionRepository;
import co.edu.icesi.student360.auth.domain.port.LoginAttemptLimiter;
import co.edu.icesi.student360.auth.domain.port.PasswordHasher;
import co.edu.icesi.student360.auth.domain.port.RefreshTokenRepository;
import co.edu.icesi.student360.common.api.exception.AuthenticationFailedException;
import co.edu.icesi.student360.common.audit.AuditTrail;
import co.edu.icesi.student360.common.audit.AuthorizationBasis;
import co.edu.icesi.student360.common.audit.Outcome;
import co.edu.icesi.student360.common.audit.RecordType;
import co.edu.icesi.student360.common.identity.Identity;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

/**
 * Login, refresh-token rotation with reuse detection, logout. Every security event — failures
 * included — leaves a SECURITY audit record.
 */
public class AuthenticationService {

  static final String INVALID_CREDENTIALS = "Invalid credentials";
  static final String INVALID_REFRESH_TOKEN = "Invalid refresh token";

  private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

  private final AppUserRepository users;
  private final AuthSessionRepository sessions;
  private final RefreshTokenRepository refreshTokens;
  private final AccessTokenIssuer accessTokens;
  private final PasswordHasher passwords;
  private final LoginAttemptLimiter limiter;
  private final RefreshTokenCodec codec;
  private final AuditTrail audit;
  private final Clock clock;
  private final Duration refreshTokenTimeToLive;

  public AuthenticationService(
      AppUserRepository users,
      AuthSessionRepository sessions,
      RefreshTokenRepository refreshTokens,
      AccessTokenIssuer accessTokens,
      PasswordHasher passwords,
      LoginAttemptLimiter limiter,
      RefreshTokenCodec codec,
      AuditTrail audit,
      Clock clock,
      Duration refreshTokenTimeToLive) {
    this.users = users;
    this.sessions = sessions;
    this.refreshTokens = refreshTokens;
    this.accessTokens = accessTokens;
    this.passwords = passwords;
    this.limiter = limiter;
    this.codec = codec;
    this.audit = audit;
    this.clock = clock;
    this.refreshTokenTimeToLive = refreshTokenTimeToLive;
  }

  @Transactional(noRollbackFor = AuthenticationFailedException.class)
  public TokenPair login(String email, String password, String userAgent, String sourceIp) {
    String limiterKey = email.toLowerCase(Locale.ROOT) + "|" + sourceIp;
    limiter.assertAllowed(limiterKey);

    Optional<AppUser> candidate = users.findByEmailIgnoreCase(email).filter(AppUser::isActive);
    // The hash is checked even for unknown users so response time does not reveal which
    // e-mails exist.
    boolean matches =
        candidate.map(user -> passwords.matches(password, user.getPasswordHash())).orElse(false);
    if (!matches) {
      limiter.recordFailure(limiterKey);
      audit.recordAs(
          candidate.map(this::identityOf).orElse(null),
          RecordType.SECURITY,
          "LOGIN_FAILED",
          "SESSION",
          null,
          AuthorizationBasis.NONE,
          Outcome.DENIED,
          Map.of("reason", candidate.isPresent() ? "BAD_PASSWORD" : "UNKNOWN_USER"));
      throw new AuthenticationFailedException(INVALID_CREDENTIALS);
    }
    limiter.reset(limiterKey);

    AppUser user = candidate.orElseThrow();
    Instant now = clock.instant();
    AuthSession session = sessions.save(AuthSession.open(user, now, userAgent, sourceIp));
    TokenPair pair = issuePair(user, session, now);
    audit.recordAs(
        identityOf(user),
        RecordType.SECURITY,
        "LOGIN_SUCCEEDED",
        "SESSION",
        session.getId().toString(),
        AuthorizationBasis.SELF,
        Outcome.ALLOWED,
        Map.of());
    log.info("Session {} opened for user {}", session.getId(), user.getId());
    return pair;
  }

  /**
   * The rotation algorithm (context document §1.5). Runs in one transaction with the token row
   * locked; a detected reuse must commit the revocation while the caller still receives 401, hence
   * {@code noRollbackFor}.
   */
  @Transactional(noRollbackFor = AuthenticationFailedException.class)
  public TokenPair refresh(String rawRefreshToken) {
    Instant now = clock.instant();
    RefreshToken presented =
        refreshTokens
            .findByTokenHashForUpdate(codec.hash(rawRefreshToken))
            .orElseThrow(() -> rejectRefresh(null, "UNKNOWN_TOKEN"));
    AuthSession session = presented.getSession();
    AppUser user = session.getUser();

    // A dead family stays dead: tokens of a revoked session are rejected as such, and only a
    // consumed token of a *live* session counts as reuse. Otherwise every later replay of the
    // same family would be recorded as a fresh incident.
    if (session.isRevoked()) {
      throw rejectRefresh(user, "SESSION_REVOKED");
    }
    if (presented.isUsed()) {
      // Either an attacker used it first or the legitimate user did: indistinguishable, so the
      // whole family dies and both parties lose access.
      session.revoke(RevocationReason.REUSE_DETECTED, now);
      int invalidated = refreshTokens.invalidateFamily(session.getId(), now);
      audit.recordAs(
          identityOf(user),
          RecordType.SECURITY,
          "REFRESH_TOKEN_REUSED",
          "SESSION",
          session.getId().toString(),
          AuthorizationBasis.NONE,
          Outcome.DENIED,
          Map.of("tokensInvalidated", invalidated, "presentedTokenId", presented.getId()));
      log.warn("Refresh token reuse detected; session {} revoked", session.getId());
      throw new AuthenticationFailedException(INVALID_REFRESH_TOKEN);
    }
    if (presented.isExpired(now)) {
      throw rejectRefresh(user, "TOKEN_EXPIRED");
    }

    TokenPair pair = issuePair(user, session, now, presented);
    audit.recordAs(
        identityOf(user),
        RecordType.SECURITY,
        "TOKEN_REFRESHED",
        "SESSION",
        session.getId().toString(),
        AuthorizationBasis.SELF,
        Outcome.ALLOWED,
        Map.of());
    return pair;
  }

  /** Idempotent: an unknown or already-revoked token is not an error worth revealing. */
  @Transactional
  public void logout(String rawRefreshToken) {
    Instant now = clock.instant();
    refreshTokens
        .findByTokenHashForUpdate(codec.hash(rawRefreshToken))
        .ifPresent(
            token -> {
              AuthSession session = token.getSession();
              if (session.isRevoked()) {
                return;
              }
              session.revoke(RevocationReason.LOGOUT, now);
              refreshTokens.invalidateFamily(session.getId(), now);
              audit.recordAs(
                  identityOf(session.getUser()),
                  RecordType.SECURITY,
                  "SESSION_REVOKED",
                  "SESSION",
                  session.getId().toString(),
                  AuthorizationBasis.SELF,
                  Outcome.ALLOWED,
                  Map.of("reason", RevocationReason.LOGOUT.name()));
            });
  }

  @Transactional(readOnly = true)
  public UserProfile profile(String accessToken) {
    AccessTokenClaims claims = accessTokens.verify(accessToken);
    AppUser user =
        users
            .findById(claims.subject())
            .filter(AppUser::isActive)
            .orElseThrow(() -> new AuthenticationFailedException("Unknown user"));
    return new UserProfile(
        user.getId(),
        user.getEmail(),
        user.getFullName(),
        user.roleNames(),
        user.getExternalReference());
  }

  private TokenPair issuePair(AppUser user, AuthSession session, Instant now) {
    return issuePair(user, session, now, null);
  }

  private TokenPair issuePair(
      AppUser user, AuthSession session, Instant now, RefreshToken previous) {
    String rawRefresh = codec.generate();
    Instant refreshExpiresAt = now.plus(refreshTokenTimeToLive);
    RefreshToken next =
        refreshTokens.save(
            RefreshToken.issue(session, codec.hash(rawRefresh), now, refreshExpiresAt));
    if (previous != null) {
      previous.markUsed(now, next);
    }
    IssuedAccessToken access = accessTokens.issue(user, session.getId());
    return new TokenPair(
        access.value(), access.expiresAt(), rawRefresh, refreshExpiresAt, session.getId());
  }

  private AuthenticationFailedException rejectRefresh(AppUser user, String reason) {
    audit.recordAs(
        user == null ? null : identityOf(user),
        RecordType.SECURITY,
        "REFRESH_REJECTED",
        "SESSION",
        null,
        AuthorizationBasis.NONE,
        Outcome.DENIED,
        Map.of("reason", reason));
    return new AuthenticationFailedException(INVALID_REFRESH_TOKEN);
  }

  private Identity identityOf(AppUser user) {
    return new Identity(user.getId(), user.roleNames(), user.getExternalReference());
  }
}
