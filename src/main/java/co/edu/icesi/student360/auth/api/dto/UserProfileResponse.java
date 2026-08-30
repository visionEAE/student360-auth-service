package co.edu.icesi.student360.auth.api.dto;

import co.edu.icesi.student360.auth.domain.model.UserProfile;
import java.util.Set;

public record UserProfileResponse(
    String id, String email, String fullName, Set<String> roles, String externalReference) {

  public static UserProfileResponse from(UserProfile profile) {
    return new UserProfileResponse(
        profile.id().toString(),
        profile.email(),
        profile.fullName(),
        profile.roles(),
        profile.externalReference());
  }
}
