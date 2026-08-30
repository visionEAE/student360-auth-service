package co.edu.icesi.student360.auth.support;

import co.edu.icesi.student360.auth.domain.model.SigningKey;
import co.edu.icesi.student360.auth.domain.port.SigningKeyProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/** A throwaway key pair per test JVM, so no private key ever needs to live in the repository. */
@TestConfiguration
public class TestSigningKeyConfiguration {

  @Bean
  @Primary
  public SigningKeyProvider testSigningKeyProvider() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair pair = generator.generateKeyPair();
    SigningKey key =
        new SigningKey(
            "test-key", (RSAPrivateKey) pair.getPrivate(), (RSAPublicKey) pair.getPublic());
    return () -> key;
  }
}
