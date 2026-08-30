package co.edu.icesi.student360.auth.domain.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** One link of a rotation chain. Only the SHA-256 of the opaque value is ever stored. */
@Entity
@Table(name = "refresh_token", schema = "auth")
public class RefreshToken {

  @Id private UUID id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "session_id", nullable = false)
  private AuthSession session;

  @Column(name = "token_hash", nullable = false, unique = true)
  private String tokenHash;

  @Column(name = "issued_at", nullable = false)
  private Instant issuedAt;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  @Column(name = "used_at")
  private Instant usedAt;

  @Column(name = "replaced_by")
  private UUID replacedBy;

  protected RefreshToken() {}

  public static RefreshToken issue(
      AuthSession session, String tokenHash, Instant now, Instant expiresAt) {
    RefreshToken token = new RefreshToken();
    token.id = UUID.randomUUID();
    token.session = session;
    token.tokenHash = tokenHash;
    token.issuedAt = now;
    token.expiresAt = expiresAt;
    return token;
  }

  public boolean isUsed() {
    return usedAt != null;
  }

  public boolean isExpired(Instant now) {
    return !expiresAt.isAfter(now);
  }

  public void markUsed(Instant now, RefreshToken replacement) {
    this.usedAt = now;
    this.replacedBy = replacement.getId();
  }

  public UUID getId() {
    return id;
  }

  public AuthSession getSession() {
    return session;
  }

  public String getTokenHash() {
    return tokenHash;
  }

  public Instant getIssuedAt() {
    return issuedAt;
  }

  public Instant getExpiresAt() {
    return expiresAt;
  }

  public Instant getUsedAt() {
    return usedAt;
  }

  public UUID getReplacedBy() {
    return replacedBy;
  }
}
