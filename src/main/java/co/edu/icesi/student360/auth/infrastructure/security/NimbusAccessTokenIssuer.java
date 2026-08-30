package co.edu.icesi.student360.auth.infrastructure.security;

import co.edu.icesi.student360.auth.domain.model.AccessTokenClaims;
import co.edu.icesi.student360.auth.domain.model.AppUser;
import co.edu.icesi.student360.auth.domain.model.IssuedAccessToken;
import co.edu.icesi.student360.auth.domain.model.SigningKey;
import co.edu.icesi.student360.auth.domain.port.AccessTokenIssuer;
import co.edu.icesi.student360.auth.domain.port.SigningKeyProvider;
import co.edu.icesi.student360.common.api.exception.AuthenticationFailedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * RS256 access tokens with the payload the gateway and the domain services rely on: {@code roles}
 * for coarse authorization, {@code ref} for fine-grained authorization without a call back to the
 * SSO, {@code sid} to tie the token to its refresh family, {@code jti} for audit correlation.
 */
public class NimbusAccessTokenIssuer implements AccessTokenIssuer {

  static final String ROLES_CLAIM = "roles";
  static final String REFERENCE_CLAIM = "ref";
  static final String SESSION_CLAIM = "sid";

  private final SigningKey key;
  private final RSASSASigner signer;
  private final JWSVerifier verifier;
  private final JWKSet jwkSet;
  private final String issuer;
  private final String audience;
  private final Duration timeToLive;
  private final Clock clock;

  public NimbusAccessTokenIssuer(
      SigningKeyProvider keys, String issuer, String audience, Duration timeToLive, Clock clock) {
    this.key = keys.signingKey();
    this.signer = new RSASSASigner(key.privateKey());
    this.verifier = new RSASSAVerifier(key.publicKey());
    this.jwkSet =
        new JWKSet(
            new RSAKey.Builder(key.publicKey())
                .keyID(key.keyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build());
    this.issuer = issuer;
    this.audience = audience;
    this.timeToLive = timeToLive;
    this.clock = clock;
  }

  @Override
  public IssuedAccessToken issue(AppUser user, UUID sessionId) {
    Instant now = clock.instant();
    Instant expiresAt = now.plus(timeToLive);
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(user.getId().toString())
            .audience(audience)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(expiresAt))
            .jwtID(UUID.randomUUID().toString())
            .claim(ROLES_CLAIM, List.copyOf(user.roleNames()))
            .claim(REFERENCE_CLAIM, user.getExternalReference())
            .claim(SESSION_CLAIM, sessionId.toString())
            .build();
    SignedJWT jwt =
        new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyId()).build(), claims);
    try {
      jwt.sign(signer);
    } catch (JOSEException exception) {
      throw new IllegalStateException("Cannot sign access token", exception);
    }
    return new IssuedAccessToken(jwt.serialize(), expiresAt);
  }

  @Override
  public AccessTokenClaims verify(String token) {
    try {
      SignedJWT jwt = SignedJWT.parse(token);
      if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm()) || !jwt.verify(verifier)) {
        throw new AuthenticationFailedException("Invalid access token");
      }
      JWTClaimsSet claims = jwt.getJWTClaimsSet();
      Date expiration = claims.getExpirationTime();
      if (expiration == null || !expiration.toInstant().isAfter(clock.instant())) {
        throw new AuthenticationFailedException("Expired access token");
      }
      if (!issuer.equals(claims.getIssuer()) || !claims.getAudience().contains(audience)) {
        throw new AuthenticationFailedException("Invalid access token");
      }
      List<String> roles = claims.getStringListClaim(ROLES_CLAIM);
      return new AccessTokenClaims(
          UUID.fromString(claims.getSubject()),
          UUID.fromString(claims.getStringClaim(SESSION_CLAIM)),
          roles == null ? Set.of() : Set.copyOf(roles),
          claims.getStringClaim(REFERENCE_CLAIM),
          claims.getJWTID());
    } catch (ParseException | JOSEException | IllegalArgumentException exception) {
      throw new AuthenticationFailedException("Invalid access token");
    }
  }

  @Override
  public Map<String, Object> publicKeys() {
    return jwkSet.toJSONObject(true);
  }
}
