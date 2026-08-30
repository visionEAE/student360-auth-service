package co.edu.icesi.student360.auth.domain.port;

import co.edu.icesi.student360.auth.domain.model.SigningKey;

/**
 * Port: where the signing key comes from. Stage 1 reads a PEM file whose path is configuration;
 * stage 2 reads the same PEM from Secret Manager. The issuer does not change.
 */
public interface SigningKeyProvider {

  SigningKey signingKey();
}
