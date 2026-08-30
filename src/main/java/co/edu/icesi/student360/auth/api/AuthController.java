package co.edu.icesi.student360.auth.api;

import co.edu.icesi.student360.auth.api.dto.LoginRequest;
import co.edu.icesi.student360.auth.api.dto.RefreshRequest;
import co.edu.icesi.student360.auth.api.dto.TokenResponse;
import co.edu.icesi.student360.auth.api.dto.UserProfileResponse;
import co.edu.icesi.student360.auth.domain.model.TokenPair;
import co.edu.icesi.student360.auth.domain.service.AuthenticationService;
import co.edu.icesi.student360.common.api.exception.AuthenticationFailedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private static final String BEARER_PREFIX = "Bearer ";

  private final AuthenticationService authentication;
  private final RefreshCookies cookies;
  private final Clock clock;

  public AuthController(AuthenticationService authentication, RefreshCookies cookies, Clock clock) {
    this.authentication = authentication;
    this.cookies = cookies;
    this.clock = clock;
  }

  @PostMapping("/login")
  public ResponseEntity<TokenResponse> login(
      @Valid @RequestBody LoginRequest body,
      @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent,
      HttpServletRequest request) {
    TokenPair pair =
        authentication.login(body.email(), body.password(), userAgent, sourceIp(request));
    return respondWith(pair);
  }

  @PostMapping("/refresh")
  public ResponseEntity<TokenResponse> refresh(
      @Valid @RequestBody(required = false) RefreshRequest body, HttpServletRequest request) {
    String refreshToken =
        presentedRefreshToken(body, request)
            .orElseThrow(() -> new AuthenticationFailedException("Missing refresh token"));
    return respondWith(authentication.refresh(refreshToken));
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(
      @Valid @RequestBody(required = false) RefreshRequest body, HttpServletRequest request) {
    presentedRefreshToken(body, request).ifPresent(authentication::logout);
    return ResponseEntity.noContent()
        .header(HttpHeaders.SET_COOKIE, cookies.clear().toString())
        .build();
  }

  @GetMapping("/me")
  public UserProfileResponse me(
      @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
    if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
      throw new AuthenticationFailedException("Missing access token");
    }
    return UserProfileResponse.from(
        authentication.profile(authorization.substring(BEARER_PREFIX.length())));
  }

  private ResponseEntity<TokenResponse> respondWith(TokenPair pair) {
    Instant now = clock.instant();
    return ResponseEntity.ok()
        .header(
            HttpHeaders.SET_COOKIE,
            cookies.issue(pair.refreshToken(), pair.refreshTokenExpiresAt(), now).toString())
        .body(TokenResponse.from(pair, now));
  }

  private Optional<String> presentedRefreshToken(RefreshRequest body, HttpServletRequest request) {
    if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
      return Optional.of(body.refreshToken());
    }
    return cookies.read(request);
  }

  private static String sourceIp(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For");
    if (forwarded != null && !forwarded.isBlank()) {
      return forwarded.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
