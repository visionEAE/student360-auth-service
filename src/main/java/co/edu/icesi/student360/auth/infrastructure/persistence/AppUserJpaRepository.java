package co.edu.icesi.student360.auth.infrastructure.persistence;

import co.edu.icesi.student360.auth.domain.model.AppUser;
import co.edu.icesi.student360.auth.domain.port.AppUserRepository;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data derives the implementation of the port from the method names. */
public interface AppUserJpaRepository extends JpaRepository<AppUser, UUID>, AppUserRepository {}
