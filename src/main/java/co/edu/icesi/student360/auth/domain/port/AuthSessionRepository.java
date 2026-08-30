package co.edu.icesi.student360.auth.domain.port;

import co.edu.icesi.student360.auth.domain.model.AuthSession;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository {

  AuthSession save(AuthSession session);

  Optional<AuthSession> findById(UUID id);
}
