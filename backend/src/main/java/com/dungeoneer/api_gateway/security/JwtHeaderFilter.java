package com.dungeoneer.api_gateway.security;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class JwtHeaderFilter extends OncePerRequestFilter {

    private static final String HEADER_X_USER_ID = "X-User-Id";
    private static final String HEADER_X_USER_ROLES = "X-User-Roles";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final byte[] secretKeyBytes;
    private final Set<String> allowedOrigins;

    public JwtHeaderFilter(
            @Value("${jwt.secret}") String jwtSecret,
            @Value("${cors.allowed-origins:http://localhost:3000,http://127.0.0.1:3000}") String allowedOriginsConfig) {
        Objects.requireNonNull(jwtSecret, "jwt.secret must not be null");
        this.secretKeyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        if (this.secretKeyBytes.length < 32) {
            throw new IllegalStateException("JWT_SECRET must be at least 256 bits (32 bytes)");
        }

        Set<String> origins = new HashSet<>();
        if (allowedOriginsConfig != null) {
            Arrays.stream(allowedOriginsConfig.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .forEach(origins::add);
        }
        this.allowedOrigins = Collections.unmodifiableSet(origins);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Allow preflight OPTIONS requests to proceed directly for CORS handling
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        String method = request.getMethod();

        boolean isCharacterProtected = isCharacterRoute(path);
        boolean isReferenceMutation = isReferenceMutationRoute(path, method);
        boolean isAuthProtected = isAuthProtectedRoute(path);
        boolean isProtected = isCharacterProtected || isReferenceMutation || isAuthProtected;

        UUID verifiedUserId = null;
        List<String> verifiedRoles = null;

        String authHeader = request.getHeader(HEADER_AUTHORIZATION);
        boolean hasBearerToken = authHeader != null && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length());

        if (isProtected || hasBearerToken) {
            if (isProtected && !hasBearerToken) {
                sendUnauthorized(request, response, path, "Missing or invalid Authorization header");
                return;
            }

            if (hasBearerToken) {
                String token = authHeader.substring(BEARER_PREFIX.length()).trim();
                while (token.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                    token = token.substring(BEARER_PREFIX.length()).trim();
                }
                try {
                    SignedJWT signedJWT = SignedJWT.parse(token);
                    JWSVerifier verifier = new MACVerifier(this.secretKeyBytes);

                    if (!signedJWT.verify(verifier)) {
                        if (isProtected) {
                            sendUnauthorized(request, response, path, "Invalid token signature");
                            return;
                        }
                    } else {
                        Date exp = signedJWT.getJWTClaimsSet().getExpirationTime();
                        if (exp == null || exp.before(new Date())) {
                            if (isProtected) {
                                sendUnauthorized(request, response, path, "Token has expired");
                                return;
                            }
                        } else {
                            String sub = signedJWT.getJWTClaimsSet().getSubject();
                            if (sub == null || sub.isBlank()) {
                                if (isProtected) {
                                    sendUnauthorized(request, response, path, "Token missing subject claim");
                                    return;
                                }
                            } else {
                                verifiedUserId = UUID.fromString(sub);
                                List<String> rolesClaim = signedJWT.getJWTClaimsSet().getStringListClaim("roles");
                                if (rolesClaim != null) {
                                    verifiedRoles = rolesClaim;
                                }
                            }
                        }
                    }
                } catch (Exception ex) {
                    if (isProtected) {
                        sendUnauthorized(request, response, path, "Token validation failed: " + ex.getMessage());
                        return;
                    }
                }
            }
        }

        // Enforce DUNGEON_MASTER role on reference mutations
        if (isReferenceMutation) {
            if (verifiedUserId == null) {
                sendUnauthorized(request, response, path, "Authentication required for reference creation");
                return;
            }
            if (verifiedRoles == null || !verifiedRoles.contains("DUNGEON_MASTER")) {
                sendForbidden(request, response, path, "Only users with DUNGEON_MASTER role can create reference content");
                return;
            }
        }

        // Unconditionally strip client-supplied X-User-Id / X-User-Roles and only inject verified perimeter headers
        HeaderModifyingRequestWrapper wrappedRequest = new HeaderModifyingRequestWrapper(request, verifiedUserId, verifiedRoles);
        filterChain.doFilter(wrappedRequest, response);
    }

    private boolean isCharacterRoute(String path) {
        return path != null && path.startsWith("/api/characters");
    }

    private boolean isAuthProtectedRoute(String path) {
        return path != null && path.startsWith("/api/auth/me");
    }

    private boolean isReferenceMutationRoute(String path, String method) {
        if (path == null || !path.startsWith("/api/reference")) {
            return false;
        }
        return "POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method);
    }

    private void applyCorsHeaders(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("Origin");
        if (origin != null && this.allowedOrigins.contains(origin)) {
            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
            response.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH,OPTIONS");
            response.setHeader("Access-Control-Allow-Headers", "Authorization,Content-Type,X-User-Id,Accept,Origin");
            response.setHeader("Vary", "Origin");
        }
    }

    private void sendUnauthorized(HttpServletRequest request, HttpServletResponse response, String instance, String detail) throws IOException {
        applyCorsHeaders(request, response);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/problem+json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        String json = String.format(
                "{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401,\"detail\":\"%s\",\"instance\":\"%s\"}",
                escapeJson(detail),
                escapeJson(instance)
        );
        response.getWriter().write(json);
    }

    private void sendForbidden(HttpServletRequest request, HttpServletResponse response, String instance, String detail) throws IOException {
        applyCorsHeaders(request, response);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/problem+json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        String json = String.format(
                "{\"type\":\"about:blank\",\"title\":\"Forbidden\",\"status\":403,\"detail\":\"%s\",\"instance\":\"%s\"}",
                escapeJson(detail),
                escapeJson(instance)
        );
        response.getWriter().write(json);
    }

    private String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /**
     * Request wrapper that filters out untrusted headers and injects verified perimeter headers.
     */
    static class HeaderModifyingRequestWrapper extends HttpServletRequestWrapper {

        private final Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        HeaderModifyingRequestWrapper(HttpServletRequest request, UUID verifiedUserId, List<String> verifiedRoles) {
            super(request);

            Enumeration<String> headerNames = request.getHeaderNames();
            if (headerNames != null) {
                while (headerNames.hasMoreElements()) {
                    String name = headerNames.nextElement();
                    // Strip incoming X-User-Id and X-User-Roles
                    if (!HEADER_X_USER_ID.equalsIgnoreCase(name) && !HEADER_X_USER_ROLES.equalsIgnoreCase(name)) {
                        List<String> values = Collections.list(request.getHeaders(name));
                        this.headers.put(name, values);
                    }
                }
            }

            // Inject verified X-User-Id only if authenticated
            if (verifiedUserId != null) {
                this.headers.put(HEADER_X_USER_ID, List.of(verifiedUserId.toString()));
            }

            // Inject verified X-User-Roles only if authenticated
            if (verifiedRoles != null && !verifiedRoles.isEmpty()) {
                this.headers.put(HEADER_X_USER_ROLES, List.of(String.join(",", verifiedRoles)));
            }
        }

        @Override
        public String getHeader(String name) {
            List<String> values = this.headers.get(name);
            return (values != null && !values.isEmpty()) ? values.get(0) : null;
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            List<String> values = this.headers.get(name);
            return values != null ? Collections.enumeration(values) : Collections.emptyEnumeration();
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            return Collections.enumeration(this.headers.keySet());
        }
    }
}
