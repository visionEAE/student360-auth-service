package co.edu.icesi.student360.auth.infrastructure.persistence;

import co.edu.icesi.student360.auth.domain.model.RefreshToken;
import co.edu.icesi.student360.auth.domain.port.RefreshTokenRepository;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenJpaRepository
    extends JpaRepository<RefreshToken, UUID>, RefreshTokenRepository {

  /** {@code SELECT ... FOR UPDATE}: concurrent refreshes of one token serialise on this row. */
  @Override
  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query(
      "select t from RefreshToken t"
          + " join fetch t.session s join fetch s.user"
          + " where t.tokenHash = :hash")
  Optional<RefreshToken> findByTokenHashForUpdate(@Param("hash") String tokenHash);

  @Override
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Query(
      "update RefreshToken t set t.usedAt = :now"
          + " where t.session.id = :sessionId and t.usedAt is null")
  int invalidateFamily(@Param("sessionId") UUID sessionId, @Param("now") Instant now);
}
