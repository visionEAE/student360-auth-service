package co.edu.icesi.student360.auth.domain.model;

import java.util.Set;
import java.util.UUID;

public record UserProfile(
    UUID id, String email, String fullName, Set<String> roles, String externalReference) {}
