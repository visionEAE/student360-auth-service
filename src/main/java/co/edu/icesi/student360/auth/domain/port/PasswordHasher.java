package co.edu.icesi.student360.auth.domain.port;

public interface PasswordHasher {

  boolean matches(String rawPassword, String passwordHash);
}
