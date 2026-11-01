package com.dungeoneer.api_gateway.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class HomebrewGatewaySecurityTest {

    private static final String TEST_SECRET = "0123456789012345678901234567890123456789";

    private JwtHeaderFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtHeaderFilter(TEST_SECRET, "http://localhost:3000,http://127.0.0.1:3000");
    }

    private String generateToken(UUID userId, List<String> roles) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(userId.toString())
                .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                .issueTime(new Date());

        if (roles != null) {
            builder.claim("roles", roles);
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), builder.build());
        signedJWT.sign(new MACSigner(TEST_SECRET.getBytes(StandardCharsets.UTF_8)));
        return signedJWT.serialize();
    }

    @Test
    @DisplayName("POST /api/reference/spells without JWT returns 401 Unauthorized")
    void referenceMutationWithoutAuthReturns401() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/reference/spells");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith("application/problem+json");
    }

    @Test
    @DisplayName("POST /api/reference/spells with PLAYER role returns 403 Forbidden")
    void referenceMutationWithPlayerRoleReturns403() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = generateToken(userId, List.of("PLAYER"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/reference/spells");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(response.getContentAsString()).contains("DUNGEON_MASTER");
    }

    @Test
    @DisplayName("POST /api/reference/spells with DUNGEON_MASTER role passes and injects X-User-Id and X-User-Roles")
    void referenceMutationWithDmRoleSucceedsAndInjectsHeaders() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = generateToken(userId, List.of("DUNGEON_MASTER", "PLAYER"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/reference/spells");
        request.addHeader("Authorization", "Bearer " + token);
        request.addHeader("X-User-Id", UUID.randomUUID().toString()); // spoof attempt

        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<HttpServletRequest> forwardedRequest = new AtomicReference<>();
        FilterChain chain = (req, res) -> forwardedRequest.set((HttpServletRequest) req);

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(forwardedRequest.get()).isNotNull();
        assertThat(forwardedRequest.get().getHeader("X-User-Id")).isEqualTo(userId.toString());
        assertThat(forwardedRequest.get().getHeader("X-User-Roles")).contains("DUNGEON_MASTER");
    }

    @Test
    @DisplayName("GET /api/reference/spells with JWT propagates X-User-Id")
    void referenceGetWithJwtPropagatesXUserId() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = generateToken(userId, List.of("PLAYER"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/reference/spells");
        request.addHeader("Authorization", "Bearer " + token);

        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<HttpServletRequest> forwardedRequest = new AtomicReference<>();
        FilterChain chain = (req, res) -> forwardedRequest.set((HttpServletRequest) req);

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(forwardedRequest.get().getHeader("X-User-Id")).isEqualTo(userId.toString());
    }

    @Test
    @DisplayName("POST /api/reference/spells without JWT and with valid Origin returns 401 with CORS headers")
    void referenceMutationWithoutAuthHasCorsHeaders() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/reference/spells");
        request.addHeader("Origin", "http://localhost:3000");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("Access-Control-Allow-Origin")).isEqualTo("http://localhost:3000");
        assertThat(response.getHeader("Access-Control-Allow-Credentials")).isEqualTo("true");
        assertThat(response.getHeader("Vary")).isEqualTo("Origin");
    }

    @Test
    @DisplayName("POST /api/reference/spells with PLAYER role and valid Origin returns 403 with CORS headers")
    void referenceMutationWithPlayerRoleHasCorsHeaders() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = generateToken(userId, List.of("PLAYER"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/reference/spells");
        request.addHeader("Authorization", "Bearer " + token);
        request.addHeader("Origin", "http://localhost:3000");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getHeader("Access-Control-Allow-Origin")).isEqualTo("http://localhost:3000");
        assertThat(response.getHeader("Access-Control-Allow-Credentials")).isEqualTo("true");
        assertThat(response.getHeader("Vary")).isEqualTo("Origin");
    }
}
