package com.brsm.apigateway.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import io.jsonwebtoken.*;

import java.util.Map;
import java.util.Set;

@Slf4j
@Component
public class JwtAuthFilter implements GlobalFilter {

    @Value("${jwt.secret}")
    private String SECRET;

    private static final Map<String, Set<String>> PATH_ROLES = Map.of(
            "/auth/create", Set.of("CHIEF_SECRETARY")
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (path.equals("/auth/login")) {
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);
        if (token == null) {
            return unauthorized(exchange, "Missing token");
        }

        try {
            Claims claims = parseToken(token);
            String role = claims.get("role", String.class);

            if (!hasAccess(path, role)) {
                return forbidden(exchange, "Access denied for role: " + role);
            }

            ServerHttpRequest mutated = request.mutate()
                    .header("X-User-Name", claims.getSubject())
                    .header("X-User-Role", role)
                    .header("X-Student-Id", claims.get("studentId", Integer.class).toString())
                    .build();

            return chain.filter(exchange.mutate().request(mutated).build());

        } catch (Exception e) {
            return unauthorized(exchange, "Invalid token");
        }
    }

    private String extractToken(ServerWebExchange exchange) {
        String auth = exchange.getRequest().getHeaders().getFirst("Authorization");
        return (auth != null && auth.startsWith("Bearer ")) ? auth.substring(7) : null;
    }

    private Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET)))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean hasAccess(String path, String role) {
        return PATH_ROLES.entrySet().stream()
                .filter(entry -> pathMatches(path, entry.getKey()))
                .anyMatch(entry -> entry.getValue().contains(role));
    }

    private boolean pathMatches(String path, String pattern) {
        if (pattern.endsWith("/**")) {
            String prefix = pattern.substring(0, pattern.length() - 3);
            return path.startsWith(prefix);
        }
        return path.equals(pattern) || path.startsWith(pattern + "/");
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String msg) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        return exchange.getResponse().writeWith(Mono.just(
                exchange.getResponse().bufferFactory().wrap(
                        ("{\"error\": \"" + msg + "\"}").getBytes()
                )
        ));
    }

    private Mono<Void> forbidden(ServerWebExchange exchange, String msg) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        return exchange.getResponse().writeWith(Mono.just(
                exchange.getResponse().bufferFactory().wrap(
                        ("{\"error\": \"" + msg + "\"}").getBytes()
                )
        ));
    }
}
