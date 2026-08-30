# student360-auth-service

Custom SSO for Student 360° (port **8081**, schema **`auth`**). Issues 15-minute RS256 access
tokens and 7-day **opaque, rotating** refresh tokens; detects refresh-token reuse and revokes the
whole token family; publishes its public key as JWKS. Every security event — failures included —
is written to the shared audit trail.

| Method | Path | Auth | Notes |
|---|---|---|---|
| `POST` | `/api/auth/login` | credentials | creates a session (token family); rate-limited per e-mail + ip |
| `POST` | `/api/auth/refresh` | refresh token (cookie or body) | rotates; replaying a consumed token revokes the family |
| `POST` | `/api/auth/logout` | refresh token | revokes the family; always `204` |
| `GET` | `/api/auth/me` | `Bearer <access token>` | profile from the token |
| `GET` | `/.well-known/jwks.json` | none | the only contract the gateway depends on |

Access token payload: `iss`, `sub` (user id), `aud = student360-api`, `exp`, `iat`, `jti`,
`roles`, `ref` (student/advisor id in the domain services), `sid` (session id).

## Decisions worth explaining

* **Refresh tokens are opaque and stored hashed** (`RefreshTokenCodec`): 256 random bits, SHA-256
  in the database. A leaked table yields nothing usable. Access tokens are JWTs because they must
  be verifiable without a database round trip.
* **Rotation runs under `SELECT … FOR UPDATE`** (`RefreshTokenJpaRepository`): concurrent
  refreshes of one token serialise, so exactly one succeeds and the family is never forked.
* **Reuse kills the family** (`AuthenticationService.refresh`): a consumed token reappearing means
  either the attacker or the victim arrived second — indistinguishable — so the session is revoked
  with `REUSE_DETECTED`, every token of the family is invalidated, and a `SECURITY` audit record is
  written. The transaction commits although the caller receives `401` (`noRollbackFor`).
* **Public endpoints by design**: login, refresh, logout and JWKS carry no service token; they are
  the front door, protected by credentials, rotation and rate limiting.
* **Explicit `kid`** on the single key, so rotating keys later never breaks verification.

## Ports → adapters (stage 2 swaps happen in `AuthConfiguration` only)

| Port | Stage 1 | Stage 2 |
|---|---|---|
| `SigningKeyProvider` | `PemSigningKeyProvider` (path from env) | Secret Manager |
| `LoginAttemptLimiter` | `InMemoryLoginAttemptLimiter` | shared store (Memorystore) |
| `AccessTokenIssuer` | `NimbusAccessTokenIssuer` | unchanged |
| `AuditWriter` (common) | JDBC into `audit.audit_record` | + Cloud Storage export |

## Run locally

```bash
cd ../student360-infra && make up && make keys && make build-common && make run-auth-service
```

Seeded users (password `student360`): `ana.torres@u.icesi.edu.co` (S-1001), `luis.gomez@…`
(S-1002), `maria.rojas@…` (S-1003), `carlos.mejia@icesi.edu.co` (A-2001), `diana.perez@…`
(A-2002), `admin@icesi.edu.co`. Swagger UI in the `dev` profile: `http://localhost:8081/swagger-ui.html`.

## Verify

```
mvn verify   # format, style, unit tests, Testcontainers flow tests (needs Docker)
```

`AuthenticationFlowIntegrationTest` is phase gate 1: login → JWKS verification, rotation,
reuse → family revoked + audit record, logout, concurrency, rate limiting, `/me`.
