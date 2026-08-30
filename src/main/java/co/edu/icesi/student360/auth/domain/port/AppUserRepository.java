package co.edu.icesi.student360.auth.domain.port;

import co.edu.icesi.student360.auth.domain.model.AppUser;
import java.util.Optional;
import java.util.UUID;

public interface AppUserRepository {

  Optional<AppUser> findByEmailIgnoreCase(String email);

  Optional<AppUser> findById(UUID id);
}
