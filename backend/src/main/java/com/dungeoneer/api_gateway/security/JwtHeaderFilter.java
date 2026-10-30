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
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final byte[] secretKeyBytes;

    public JwtHeaderFilter(@Value("${jwt.secret}") String jwtSecret) {
        Objects.requireNonNull(jwtSecret, "jwt.secret must not be null");
        this.secretKeyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        if (this.secretKeyBytes.length < 32) {
            throw new IllegalStateException("JWT_SECRET must be at least 256 bits (32 bytes)");
        }
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
        boolean isProtected = isProtectedRoute(path);

        UUID verifiedUserId = null;

        if (isProtected) {
            String authHeader = request.getHeader(HEADER_AUTHORIZATION);
            if (authHeader == null || !authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                sendUnauthorized(response, path, "Missing or invalid Authorization header");
                return;
            }

            String token = authHeader.substring(BEARER_PREFIX.length()).trim();
            while (token.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                token = token.substring(BEARER_PREFIX.length()).trim();
            }
            try {
                SignedJWT signedJWT = SignedJWT.parse(token);
                JWSVerifier verifier = new MACVerifier(this.secretKeyBytes);

                if (!signedJWT.verify(verifier)) {
                    sendUnauthorized(response, path, "Invalid token signature");
                    return;
                }

                Date exp = signedJWT.getJWTClaimsSet().getExpirationTime();
                if (exp == null || exp.before(new Date())) {
                    sendUnauthorized(response, path, "Token has expired");
                    return;
                }

                String sub = signedJWT.getJWTClaimsSet().getSubject();
                if (sub == null || sub.isBlank()) {
                    sendUnauthorized(response, path, "Token missing subject claim");
                    return;
                }

                verifiedUserId = UUID.fromString(sub);
            } catch (Exception ex) {
                sendUnauthorized(response, path, "Token validation failed: " + ex.getMessage());
                return;
            }
        }

        // Unconditionally strip client-supplied X-User-Id and only inject verified ID
        HeaderModifyingRequestWrapper wrappedRequest = new HeaderModifyingRequestWrapper(request, verifiedUserId);
        filterChain.doFilter(wrappedRequest, response);
    }

    private boolean isProtectedRoute(String path) {
        return path != null && path.startsWith("/api/characters");
    }

    private void sendUnauthorized(HttpServletResponse response, String instance, String detail) throws IOException {
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

        HeaderModifyingRequestWrapper(HttpServletRequest request, UUID verifiedUserId) {
            super(request);

            Enumeration<String> headerNames = request.getHeaderNames();
            if (headerNames != null) {
                while (headerNames.hasMoreElements()) {
                    String name = headerNames.nextElement();
                    // Strip incoming X-User-Id
                    if (!HEADER_X_USER_ID.equalsIgnoreCase(name)) {
                        List<String> values = Collections.list(request.getHeaders(name));
                        this.headers.put(name, values);
                    }
                }
            }

            // Inject verified X-User-Id only if authenticated
            if (verifiedUserId != null) {
                this.headers.put(HEADER_X_USER_ID, List.of(verifiedUserId.toString()));
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
