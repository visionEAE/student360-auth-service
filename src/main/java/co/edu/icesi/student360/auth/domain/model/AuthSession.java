package co.edu.icesi.student360.auth.domain.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * A refresh-token family. Every rotation stays inside the same session; revoking the session is
 * what "kill the whole family" means.
 */
@Entity
@Table(name = "auth_session", schema = "auth")
public class AuthSession {

  @Id private UUID id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "user_id", nullable = false)
  private AppUser user;

  @Column(name = "created_at", nullable = false)
  private Instant createdAt;

  @Column(name = "revoked_at")
  private Instant revokedAt;

  @Enumerated(EnumType.STRING)
  @Column(name = "revocation_reason")
  private RevocationReason revocationReason;

  @Column(name = "user_agent")
  private String userAgent;

  @Column(name = "source_ip")
  private String sourceIp;

  protected AuthSession() {}

  public static AuthSession open(AppUser user, Instant now, String userAgent, String sourceIp) {
    AuthSession session = new AuthSession();
    session.id = UUID.randomUUID();
    session.user = user;
    session.createdAt = now;
    session.userAgent = userAgent;
    session.sourceIp = sourceIp;
    return session;
  }

  public boolean isRevoked() {
    return revokedAt != null;
  }

  public void revoke(RevocationReason reason, Instant now) {
    if (!isRevoked()) {
      this.revokedAt = now;
      this.revocationReason = reason;
    }
  }

  public UUID getId() {
    return id;
  }

  public AppUser getUser() {
    return user;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }

  public Instant getRevokedAt() {
    return revokedAt;
  }

  public RevocationReason getRevocationReason() {
    return revocationReason;
  }
}
