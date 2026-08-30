package co.edu.icesi.student360.auth.domain.port;

import co.edu.icesi.student360.auth.domain.model.RefreshToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository {

  RefreshToken save(RefreshToken token);

  /**
   * Looks the token up <em>and locks its row</em> for the rest of the transaction. Two concurrent
   * refreshes of the same token must serialise, otherwise the second one is indistinguishable from
   * an attacker replaying it and a legitimate family gets destroyed.
   */
  Optional<RefreshToken> findByTokenHashForUpdate(String tokenHash);

  /** Marks every still-usable token of the family as consumed. Returns how many were. */
  int invalidateFamily(UUID sessionId, Instant now);
}
