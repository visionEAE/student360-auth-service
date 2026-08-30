package co.edu.icesi.student360.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.icesi.student360.auth.support.TestSigningKeyConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Phase gate 1 as executable checks: login issues a verifiable pair, refresh rotates, reuse revokes
 * the whole family with a SECURITY record, logout kills the session, brute force is throttled.
 */
@SpringBootTest(
    properties = {
      "AUTH_DB_PASSWORD=unused-overridden-by-testcontainers",
      "SERVICE_TOKEN_SECRET=0123456789abcdef0123456789abcdef-test-only",
      "auth.signing-key.private-key-path=/dev/null",
      "auth.signing-key.key-id=test-key",
      "auth.login-rate-limit.max-attempts=3",
      "auth.refresh-cookie.secure=false"
    })
@AutoConfigureMockMvc
@Import(TestSigningKeyConfiguration.class)
@Testcontainers
class AuthenticationFlowIntegrationTest {

  @Container @ServiceConnection
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>("postgres:16").withInitScript("db/test-init.sql");

  private static final String STUDENT_EMAIL = "ana.torres@u.icesi.edu.co";
  private static final String PASSWORD = "student360";

  @Autowired private MockMvc mockMvc;
  @Autowired private JdbcTemplate jdbc;
  @Autowired private ObjectMapper json;

  @BeforeEach
  void cleanAuditTrail() {
    jdbc.update("DELETE FROM audit.audit_record");
  }

  @Test
  void shouldIssueTokenPairOnLoginAndExposeVerifiableJwks() throws Exception {
    JsonNode tokens = login(STUDENT_EMAIL, PASSWORD);

    assertThat(tokens.path("tokenType").asText()).isEqualTo("Bearer");
    assertThat(tokens.path("expiresIn").asLong()).isBetween(890L, 900L);
    assertThat(tokens.path("refreshToken").asText()).hasSizeGreaterThanOrEqualTo(43);

    String jwks =
        mockMvc
            .perform(get("/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    RSAKey publicKey = (RSAKey) JWKSet.parse(jwks).getKeyByKeyId("test-key");
    SignedJWT jwt = SignedJWT.parse(tokens.path("accessToken").asText());
    JWSVerifier verifier = new RSASSAVerifier(publicKey);

    assertThat(jwt.verify(verifier))
        .as("access token verifies against the published JWKS")
        .isTrue();
    assertThat(jwt.getHeader().getKeyID()).isEqualTo("test-key");
    assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("student360-api");
    assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("STUDENT");
    assertThat(jwt.getJWTClaimsSet().getStringClaim("ref")).isEqualTo("S-1001");
    assertThat(jwt.getJWTClaimsSet().getJWTID()).isNotBlank();
    assertThat(auditActions()).containsExactly("LOGIN_SUCCEEDED");
  }

  @Test
  void shouldRotateRefreshTokenAndInvalidatePrevious() throws Exception {
    JsonNode first = login(STUDENT_EMAIL, PASSWORD);
    String firstRefresh = first.path("refreshToken").asText();

    JsonNode second =
        refresh(firstRefresh)
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString()
            .transform(this::read);

    assertThat(second.path("refreshToken").asText()).isNotEqualTo(firstRefresh);
    assertThat(second.path("sessionId").asText()).isEqualTo(first.path("sessionId").asText());
    refresh(firstRefresh).andExpect(status().isUnauthorized());
    Map<String, Object> chain =
        jdbc.queryForMap(
            "SELECT count(*) AS total, count(used_at) AS used, count(replaced_by) AS linked"
                + " FROM auth.refresh_token WHERE session_id = ?::uuid",
            first.path("sessionId").asText());
    assertThat(chain).containsEntry("total", 2L).containsEntry("linked", 1L);
  }

  @Test
  void shouldRevokeEntireFamilyWhenRefreshTokenIsReused() throws Exception {
    JsonNode first = login(STUDENT_EMAIL, PASSWORD);
    String consumed = first.path("refreshToken").asText();
    JsonNode second = read(refresh(consumed).andReturn().getResponse().getContentAsString());
    String sessionId = first.path("sessionId").asText();

    // The attacker (or the victim, indistinguishably) replays the consumed token.
    refresh(consumed).andExpect(status().isUnauthorized());

    // The still-fresh token of the same family is dead too: the whole session is gone.
    refresh(second.path("refreshToken").asText()).andExpect(status().isUnauthorized());
    Map<String, Object> session =
        jdbc.queryForMap(
            "SELECT revoked_at, revocation_reason FROM auth.auth_session WHERE id = ?::uuid",
            sessionId);
    assertThat(session.get("revoked_at")).isNotNull();
    assertThat(session).containsEntry("revocation_reason", "REUSE_DETECTED");
    List<Map<String, Object>> reuseRecords =
        jdbc.queryForList("SELECT * FROM audit.audit_record WHERE action = 'REFRESH_TOKEN_REUSED'");
    assertThat(reuseRecords).hasSize(1);
    assertThat(reuseRecords.get(0))
        .containsEntry("record_type", "SECURITY")
        .containsEntry("outcome", "DENIED")
        .containsEntry("subject_type", "SESSION")
        .containsEntry("subject_id", sessionId);
    assertThat(reuseRecords.get(0).get("actor_id"))
        .as("the affected user is the actor")
        .isNotNull();
  }

  @Test
  void shouldRejectRefreshAfterLogout() throws Exception {
    JsonNode tokens = login(STUDENT_EMAIL, PASSWORD);
    String refreshToken = tokens.path("refreshToken").asText();

    mockMvc
        .perform(
            post("/api/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("refreshToken", refreshToken))))
        .andExpect(status().isNoContent())
        .andExpect(
            header()
                .string(HttpHeaders.SET_COOKIE, org.hamcrest.Matchers.containsString("Max-Age=0")));

    refresh(refreshToken).andExpect(status().isUnauthorized());
    assertThat(auditActions())
        .containsExactly("LOGIN_SUCCEEDED", "SESSION_REVOKED", "REFRESH_REJECTED");
  }

  @Test
  void shouldSerialiseConcurrentRefreshesSoExactlyOneSucceeds() throws Exception {
    String refreshToken = login(STUDENT_EMAIL, PASSWORD).path("refreshToken").asText();
    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      Callable<Integer> attempt = () -> refresh(refreshToken).andReturn().getResponse().getStatus();
      List<Future<Integer>> results = executor.invokeAll(List.of(attempt, attempt));
      List<Integer> statuses = List.of(results.get(0).get(), results.get(1).get());

      // Without the row lock both could read used_at = NULL and both would be issued a new token,
      // leaving two live branches of one family. With it, the second is a reuse by definition.
      assertThat(statuses).containsExactlyInAnyOrder(200, 401);
      Long live =
          jdbc.queryForObject(
              "SELECT count(*) FROM auth.refresh_token WHERE used_at IS NULL", Long.class);
      assertThat(live).as("never more than one usable token per family").isLessThanOrEqualTo(1L);
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  void shouldAuditFailedLoginAndThrottleRepeatedAttempts() throws Exception {
    for (int attempt = 0; attempt < 3; attempt++) {
      attemptLogin("luis.gomez@u.icesi.edu.co", "wrong-password")
          .andExpect(status().isUnauthorized());
    }

    attemptLogin("luis.gomez@u.icesi.edu.co", "wrong-password")
        .andExpect(status().isTooManyRequests())
        .andExpect(header().exists(HttpHeaders.RETRY_AFTER));
    attemptLogin("nobody@u.icesi.edu.co", PASSWORD).andExpect(status().isUnauthorized());
    List<Map<String, Object>> failures =
        jdbc.queryForList(
            "SELECT actor_id, details FROM audit.audit_record WHERE action = 'LOGIN_FAILED'");
    assertThat(failures).hasSize(4);
    assertThat(failures.get(0).get("actor_id")).as("known user is recorded as actor").isNotNull();
    assertThat(failures.get(3).get("actor_id")).as("unknown user leaves no actor").isNull();
    assertThat(failures.get(3).get("details").toString()).contains("UNKNOWN_USER");
  }

  @Test
  void shouldReturnProfileForValidAccessTokenOnly() throws Exception {
    String accessToken = login(STUDENT_EMAIL, PASSWORD).path("accessToken").asText();

    mockMvc
        .perform(get("/api/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.email").value(STUDENT_EMAIL))
        .andExpect(jsonPath("$.externalReference").value("S-1001"))
        .andExpect(jsonPath("$.roles[0]").value("STUDENT"));
    mockMvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized());
    mockMvc
        .perform(get("/api/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer not.a.token"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.title").value("Authentication failed"));
  }

  private JsonNode login(String email, String password) throws Exception {
    MvcResult result =
        attemptLogin(email, password)
            .andExpect(status().isOk())
            .andExpect(
                header()
                    .string(
                        HttpHeaders.SET_COOKIE, org.hamcrest.Matchers.containsString("HttpOnly")))
            .andReturn();
    return read(result.getResponse().getContentAsString());
  }

  private org.springframework.test.web.servlet.ResultActions attemptLogin(
      String email, String password) throws Exception {
    return mockMvc.perform(
        post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .header(HttpHeaders.USER_AGENT, "integration-test")
            .content(json.writeValueAsString(Map.of("email", email, "password", password))));
  }

  private org.springframework.test.web.servlet.ResultActions refresh(String refreshToken)
      throws Exception {
    return mockMvc.perform(
        post("/api/auth/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(json.writeValueAsString(Map.of("refreshToken", refreshToken))));
  }

  private JsonNode read(String body) {
    try {
      return json.readTree(body);
    } catch (Exception exception) {
      throw new IllegalStateException(exception);
    }
  }

  private List<String> auditActions() {
    return jdbc.queryForList("SELECT action FROM audit.audit_record ORDER BY id", String.class);
  }
}
