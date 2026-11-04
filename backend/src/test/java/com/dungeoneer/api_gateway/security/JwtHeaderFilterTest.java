package com.dungeoneer.api_gateway.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
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
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class JwtHeaderFilterTest {

    private static final String TEST_SECRET = "0123456789012345678901234567890123456789"; // > 256 bits
    private static final String WRONG_SECRET = "9876543210987654321098765432109876543210";

    private JwtHeaderFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtHeaderFilter(TEST_SECRET, "http://localhost:3000,http://127.0.0.1:3000");
    }

    private String generateToken(UUID userId, Date expiration, String secret) throws Exception {
        JWSSigner(secret);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(userId.toString())
                .expirationTime(expiration)
                .issueTime(new Date())
                .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        signedJWT.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
        return signedJWT.serialize();
    }

    private void JWSSigner(String secret) {
        // no-op helper
    }

    @Test
    @DisplayName("Preflight OPTIONS requests should pass through without JWT check")
    void preflightOptionsPassThrough() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/api/characters");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("Protected route without Authorization header returns 401 ProblemDetail")
    void missingAuthHeaderReturns401() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/characters");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(response.getContentAsString()).contains("\"status\":401");
        assertThat(response.getContentAsString()).contains("Missing or invalid Authorization header");
    }

    @Test
    @DisplayName("Protected route with malformed Authorization header returns 401 ProblemDetail")
    void malformedAuthHeaderReturns401() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/characters");
        request.addHeader("Authorization", "NotBearer token123");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith("application/problem+json");
    }

    @Test
    @DisplayName("Protected route with invalid signature returns 401 ProblemDetail")
    void invalidSignatureReturns401() throws Exception {
        UUID userId = UUID.randomUUID();
        Date exp = new Date(System.currentTimeMillis() + 60_000);
        String tokenWithWrongKey = generateToken(userId, exp, WRONG_SECRET);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/characters");
        request.addHeader("Authorization", "Bearer " + tokenWithWrongKey);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("Invalid token signature");
    }

    @Test
    @DisplayName("Protected route with expired token returns 401 ProblemDetail")
    void expiredTokenReturns401() throws Exception {
        UUID userId = UUID.randomUUID();
        Date exp = new Date(System.currentTimeMillis() - 60_000); // in the past
        String expiredToken = generateToken(userId, exp, TEST_SECRET);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/characters");
        request.addHeader("Authorization", "Bearer " + expiredToken);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("Token has expired");
    }

    @Test
    @DisplayName("Protected route with valid token strips spoofed X-User-Id and injects verified subject")
    void validTokenStripsSpoofedAndInjectsVerifiedXUserId() throws Exception {
        UUID realUserId = UUID.randomUUID();
        UUID spoofedUserId = UUID.randomUUID();
        Date exp = new Date(System.currentTimeMillis() + 60_000);
        String validToken = generateToken(realUserId, exp, TEST_SECRET);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/characters");
        request.addHeader("Authorization", "Bearer " + validToken);
        request.addHeader("X-User-Id", spoofedUserId.toString());

        MockHttpServletResponse response = new MockHttpServletResponse();

        AtomicReference<HttpServletRequest> forwardedRequest = new AtomicReference<>();
        FilterChain chain = (req, res) -> forwardedRequest.set((HttpServletRequest) req);

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(forwardedRequest.get()).isNotNull();
        assertThat(forwardedRequest.get().getHeader("X-User-Id")).isEqualTo(realUserId.toString());
        assertThat(forwardedRequest.get().getHeader("X-User-Id")).isNotEqualTo(spoofedUserId.toString());
    }

    @Test
    @DisplayName("Public route strips spoofed X-User-Id without requiring token")
    void publicRouteStripsSpoofedXUserId() throws Exception {
        UUID spoofedUserId = UUID.randomUUID();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/reference/classes");
        request.addHeader("X-User-Id", spoofedUserId.toString());

        MockHttpServletResponse response = new MockHttpServletResponse();

        AtomicReference<HttpServletRequest> forwardedRequest = new AtomicReference<>();
        FilterChain chain = (req, res) -> forwardedRequest.set((HttpServletRequest) req);

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(forwardedRequest.get()).isNotNull();
        assertThat(forwardedRequest.get().getHeader("X-User-Id")).isNull();
    }
}
