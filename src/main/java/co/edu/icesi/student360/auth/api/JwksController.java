package co.edu.icesi.student360.auth.api;

import co.edu.icesi.student360.auth.domain.port.AccessTokenIssuer;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public keys, unauthenticated. This endpoint is the entire contract between the SSO and the rest
 * of the platform: point the gateway at another JWKS and the SSO is replaced.
 */
@RestController
public class JwksController {

  private final AccessTokenIssuer issuer;

  public JwksController(AccessTokenIssuer issuer) {
    this.issuer = issuer;
  }

  @GetMapping("/.well-known/jwks.json")
  public Map<String, Object> jwks() {
    return issuer.publicKeys();
  }
}
