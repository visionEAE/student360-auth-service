package co.edu.icesi.student360.auth.domain.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Refresh tokens are opaque: 256 bits of randomness, not a JWT. Only their SHA-256 is stored, so a
 * leaked database yields nothing usable. Hashing (not BCrypt) is enough because the input already
 * has full entropy — there is nothing to brute-force.
 */
public class RefreshTokenCodec {

  private static final int TOKEN_BYTES = 32;

  private final SecureRandom random = new SecureRandom();

  public String generate() {
    byte[] bytes = new byte[TOKEN_BYTES];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  public String hash(String rawToken) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(digest.digest(rawToken.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 unavailable", exception);
    }
  }
}
