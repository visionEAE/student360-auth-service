package co.edu.icesi.student360.auth.infrastructure.persistence;

import co.edu.icesi.student360.auth.domain.model.AuthSession;
import co.edu.icesi.student360.auth.domain.port.AuthSessionRepository;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthSessionJpaRepository
    extends JpaRepository<AuthSession, UUID>, AuthSessionRepository {}
