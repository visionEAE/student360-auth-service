package co.edu.icesi.student360.auth.infrastructure.security;

import co.edu.icesi.student360.auth.domain.model.SigningKey;
import co.edu.icesi.student360.auth.domain.port.SigningKeyProvider;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Stage 1 adapter: reads a PKCS#8 PEM from a path given by configuration. The public key is derived
 * from the private one, so a single file is the whole secret. Stage 2 reads the same PEM from
 * Secret Manager behind the same port.
 */
public class PemSigningKeyProvider implements SigningKeyProvider {

  private final SigningKey key;

  public PemSigningKeyProvider(Path privateKeyPath, String keyId) {
    this.key = load(privateKeyPath, keyId);
  }

  @Override
  public SigningKey signingKey() {
    return key;
  }

  private static SigningKey load(Path path, String keyId) {
    try {
      String pem = Files.readString(path, StandardCharsets.US_ASCII);
      String base64 =
          pem.replace("-----BEGIN PRIVATE KEY-----", "")
              .replace("-----END PRIVATE KEY-----", "")
              .replaceAll("\\s", "");
      KeyFactory factory = KeyFactory.getInstance("RSA");
      RSAPrivateCrtKey privateKey =
          (RSAPrivateCrtKey)
              factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
      BigInteger modulus = privateKey.getModulus();
      RSAPublicKey publicKey =
          (RSAPublicKey)
              factory.generatePublic(new RSAPublicKeySpec(modulus, privateKey.getPublicExponent()));
      return new SigningKey(keyId, privateKey, publicKey);
    } catch (IOException exception) {
      throw new IllegalStateException("Cannot read JWT signing key at " + path, exception);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | ClassCastException exception) {
      throw new IllegalStateException(
          "JWT signing key is not a PKCS#8 RSA key: " + path, exception);
    }
  }
}
