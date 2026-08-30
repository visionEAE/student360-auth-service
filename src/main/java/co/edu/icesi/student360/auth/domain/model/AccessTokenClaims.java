package co.edu.icesi.student360.auth.domain.model;

import java.util.Set;
import java.util.UUID;

/** The verified content of an access token, as the rest of the platform will read it. */
public record AccessTokenClaims(
    UUID subject, UUID sessionId, Set<String> roles, String externalReference, String tokenId) {}
