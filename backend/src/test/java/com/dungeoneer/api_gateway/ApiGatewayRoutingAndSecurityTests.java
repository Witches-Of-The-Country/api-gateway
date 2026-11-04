package com.dungeoneer.api_gateway;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class ApiGatewayRoutingAndSecurityTests {

    private static final String TEST_SECRET = "0123456789012345678901234567890123456789";

    private static HttpServer mockDownstreamServer;
    private static int downstreamPort;
    private static final AtomicReference<String> lastReceivedXUserId = new AtomicReference<>();
    private static final AtomicReference<String> lastReceivedPath = new AtomicReference<>();

    @Autowired
    private MockMvc mockMvc;

    @BeforeAll
    static void startMockDownstream() throws IOException {
        mockDownstreamServer = HttpServer.create(new InetSocketAddress(0), 0);
        downstreamPort = mockDownstreamServer.getAddress().getPort();

        mockDownstreamServer.createContext("/", exchange -> {
            lastReceivedPath.set(exchange.getRequestURI().toString());
            lastReceivedXUserId.set(exchange.getRequestHeaders().getFirst("X-User-Id"));

            byte[] responseBody = "{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, responseBody.length);
            exchange.getResponseBody().write(responseBody);
            exchange.close();
        });

        mockDownstreamServer.start();
    }

    @AfterAll
    static void stopMockDownstream() {
        if (mockDownstreamServer != null) {
            mockDownstreamServer.stop(0);
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("jwt.secret", () -> TEST_SECRET);
        registry.add("auth.service.url", () -> "http://localhost:" + downstreamPort);
        registry.add("character.service.url", () -> "http://localhost:" + downstreamPort);
        registry.add("cors.allowed-origins", () -> "http://localhost:3000");
    }

    private String generateToken(UUID userId, Date expiration, String secret) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(userId.toString())
                .expirationTime(expiration)
                .issueTime(new Date())
                .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        signedJWT.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
        return signedJWT.serialize();
    }

    @Test
    @DisplayName("TP-03: CORS preflight OPTIONS returns 200 and allowed headers for localhost:3000")
    void preflightOptionsReturnsCorsHeaders() throws Exception {
        mockMvc.perform(options("/api/characters")
                        .header(HttpHeaders.ORIGIN, "http://localhost:3000")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:3000"))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
    }

    @Test
    @DisplayName("TE-01: Protected route without token returns 401 ProblemDetail")
    void protectedRouteWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/api/characters"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Content-Type", "application/problem+json;charset=UTF-8"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.title").value("Unauthorized"))
                .andExpect(jsonPath("$.detail").value("Missing or invalid Authorization header"))
                .andExpect(jsonPath("$.instance").value("/api/characters"));
    }

    @Test
    @DisplayName("TE-01: Protected route with expired token returns 401 ProblemDetail")
    void protectedRouteWithExpiredTokenReturns401() throws Exception {
        UUID userId = UUID.randomUUID();
        Date pastDate = new Date(System.currentTimeMillis() - 60_000);
        String expiredToken = generateToken(userId, pastDate, TEST_SECRET);

        mockMvc.perform(get("/api/characters")
                        .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.detail").value("Token has expired"));
    }

    @Test
    @DisplayName("TE-02: Spoofed X-User-Id without valid token cannot bypass auth")
    void spoofedXUserIdWithoutTokenRejected() throws Exception {
        UUID spoofedUserId = UUID.randomUUID();

        mockMvc.perform(get("/api/characters")
                        .header("X-User-Id", spoofedUserId.toString()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("TP-01 & TE-02: Valid JWT on /api/characters strips spoofed X-User-Id and forwards verified sub")
    void validJwtOverridesSpoofedXUserId() throws Exception {
        UUID realUserId = UUID.randomUUID();
        UUID spoofedUserId = UUID.randomUUID();
        Date futureDate = new Date(System.currentTimeMillis() + 60_000);
        String validToken = generateToken(realUserId, futureDate, TEST_SECRET);

        lastReceivedXUserId.set(null);
        lastReceivedPath.set(null);

        mockMvc.perform(get("/api/characters")
                        .header("Authorization", "Bearer " + validToken)
                        .header("X-User-Id", spoofedUserId.toString()))
                .andExpect(status().isOk());

        assertThat(lastReceivedXUserId.get())
                .isNotNull()
                .isEqualTo(realUserId.toString())
                .isNotEqualTo(spoofedUserId.toString());
    }

    @Test
    @DisplayName("TP-02: Public auth route passes through and strips spoofed X-User-Id")
    void publicAuthRoutePassesThroughAndStripsSpoofedXUserId() throws Exception {
        UUID spoofedUserId = UUID.randomUUID();

        lastReceivedXUserId.set(null);
        lastReceivedPath.set(null);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"test\",\"password\":\"pass\"}")
                        .header("X-User-Id", spoofedUserId.toString()))
                .andExpect(status().isOk());

        assertThat(lastReceivedXUserId.get()).isNull();
        assertThat(lastReceivedPath.get()).isEqualTo("/api/auth/login");
    }

    @Test
    @DisplayName("TP-02: Public reference route passes through without token")
    void publicReferenceRoutePassesThrough() throws Exception {
        lastReceivedXUserId.set(null);
        lastReceivedPath.set(null);

        mockMvc.perform(get("/api/reference/classes"))
                .andExpect(status().isOk());

        assertThat(lastReceivedXUserId.get()).isNull();
        assertThat(lastReceivedPath.get()).isEqualTo("/api/reference/classes");
    }

    @Test
    @DisplayName("OpenAPI: Route /v3/api-docs/characters rewrites path to /v3/api-docs")
    void characterServiceOpenApiDocsRouteRewritesPath() throws Exception {
        lastReceivedPath.set(null);

        mockMvc.perform(get("/v3/api-docs/characters"))
                .andExpect(status().isOk());

        assertThat(lastReceivedPath.get()).isEqualTo("/v3/api-docs");
    }

    @Test
    @DisplayName("OpenAPI: Route /v3/api-docs/auth rewrites path to /v3/api-docs")
    void authServiceOpenApiDocsRouteRewritesPath() throws Exception {
        lastReceivedPath.set(null);

        mockMvc.perform(get("/v3/api-docs/auth"))
                .andExpect(status().isOk());

        assertThat(lastReceivedPath.get()).isEqualTo("/v3/api-docs");
    }
}
