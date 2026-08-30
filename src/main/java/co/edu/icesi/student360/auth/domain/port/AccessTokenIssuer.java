package co.edu.icesi.student360.auth.domain.port;

import co.edu.icesi.student360.auth.domain.model.AccessTokenClaims;
import co.edu.icesi.student360.auth.domain.model.AppUser;
import co.edu.icesi.student360.auth.domain.model.IssuedAccessToken;
import java.util.Map;
import java.util.UUID;

/** Port: JWT issuance and verification, and the public key set that lets others verify. */
public interface AccessTokenIssuer {

  IssuedAccessToken issue(AppUser user, UUID sessionId);

  /**
   * @throws co.edu.icesi.student360.common.api.exception.AuthenticationFailedException when the
   *     token is malformed, mis-signed, expired or for another audience
   */
  AccessTokenClaims verify(String token);

  /** The JWKS document, as a JSON-ready map. */
  Map<String, Object> publicKeys();
}
