package co.edu.icesi.student360.auth.domain.model;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * The key pair access tokens are signed with. The explicit {@code keyId} is what makes rotation
 * possible later: a new key gets a new id, and verifiers pick the right one from the JWKS.
 */
public record SigningKey(String keyId, RSAPrivateKey privateKey, RSAPublicKey publicKey) {}
