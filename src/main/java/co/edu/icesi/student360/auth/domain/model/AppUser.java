package co.edu.icesi.student360.auth.domain.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Entity
@Table(name = "app_user", schema = "auth")
public class AppUser {

  @Id private UUID id;

  @Column(nullable = false, unique = true)
  private String email;

  @Column(name = "password_hash", nullable = false)
  private String passwordHash;

  @Column(name = "full_name")
  private String fullName;

  @Column(name = "external_reference")
  private String externalReference;

  @Column(nullable = false)
  private boolean active;

  @Column(name = "created_at", nullable = false)
  private Instant createdAt;

  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
      name = "user_role",
      schema = "auth",
      joinColumns = @JoinColumn(name = "user_id"),
      inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles;

  protected AppUser() {}

  public UUID getId() {
    return id;
  }

  public String getEmail() {
    return email;
  }

  public String getPasswordHash() {
    return passwordHash;
  }

  public String getFullName() {
    return fullName;
  }

  public String getExternalReference() {
    return externalReference;
  }

  public boolean isActive() {
    return active;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }

  public Set<String> roleNames() {
    return roles.stream().map(Role::getName).collect(Collectors.toUnmodifiableSet());
  }
}
