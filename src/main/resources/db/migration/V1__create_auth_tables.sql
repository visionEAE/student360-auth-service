-- auth schema: owned by auth_user, migrated only by auth-service. Schema-qualified on purpose so
-- a migration can never land in the wrong schema.

CREATE TABLE auth.app_user (
    id                  UUID PRIMARY KEY,
    email               TEXT        NOT NULL,
    password_hash       TEXT        NOT NULL,       -- BCrypt; never logged
    full_name           TEXT,
    external_reference  TEXT,                       -- student/advisor id in core-service and lms-service
    active              BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_app_user_email UNIQUE (email)
);

CREATE TABLE auth.role (
    id    SERIAL PRIMARY KEY,
    name  TEXT NOT NULL,                            -- STUDENT | ADVISOR | ADMIN
    CONSTRAINT uq_role_name UNIQUE (name)
);

CREATE TABLE auth.user_role (
    user_id  UUID NOT NULL REFERENCES auth.app_user (id),
    role_id  INT  NOT NULL REFERENCES auth.role (id),
    PRIMARY KEY (user_id, role_id)
);

-- A session is a refresh-token FAMILY: every rotation stays inside it, and reuse kills all of it.
CREATE TABLE auth.auth_session (
    id                 UUID PRIMARY KEY,
    user_id            UUID        NOT NULL REFERENCES auth.app_user (id),
    created_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    revocation_reason  TEXT,                        -- LOGOUT | REUSE_DETECTED | EXPIRED
    user_agent         TEXT,
    source_ip          TEXT,
    CONSTRAINT chk_auth_session_reason CHECK (revocation_reason IS NULL OR revocation_reason IN ('LOGOUT', 'REUSE_DETECTED', 'EXPIRED'))
);

CREATE INDEX idx_auth_session_user ON auth.auth_session (user_id);

CREATE TABLE auth.refresh_token (
    id           UUID PRIMARY KEY,
    session_id   UUID        NOT NULL REFERENCES auth.auth_session (id),
    token_hash   TEXT        NOT NULL,              -- SHA-256 of the opaque value; the value itself is never stored
    issued_at    TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    replaced_by  UUID REFERENCES auth.refresh_token (id)
);

CREATE UNIQUE INDEX idx_refresh_token_hash    ON auth.refresh_token (token_hash);
CREATE INDEX        idx_refresh_token_session ON auth.refresh_token (session_id);
