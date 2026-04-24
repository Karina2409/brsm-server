package org.brsm_server.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {

    private static final String SECRET_KEY = "EtWBmqNcSkSZT5U1BWVwYTJaGyZz+buud4N0y1Ef4+PD+ofgl69e1a/d1SrrzyUTC5tYx714GyjdvATH+cYZy3lm2bbt9zwxVPTLzoJ0zhmc3qP9eyDXXP4sqyFL9ADhW72FCBuxXKwE22M3by3oIhOBsQ3XxeopZrwOldu+jx5HA4UJBLfOnh6n8OAnJqTomeJTH/mEX34koeP6j+EO92r3YA1BMggD6qs2xceFBOh2y4pds+8rhU1qree10oXg1D4QvWFoQKJ15kUZRbKkgtPskFSo3Rbrc+6sONyaWzBUOFhhE5ZmhhEzEGAw6Rac67JDYc1YzvIcskry1EO7mMtDeq9JUsUGNFm2TjXf+6E=\n";

    public String generateToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
        return generateToken(claims, userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails){
        log.info("Token generated for user: {}", userDetails.getUsername());
        log.info("Roles: {}", userDetails.getAuthorities());
        return Jwts
                .builder()
                .claims().add(extraClaims)
                .and()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24))
                .signWith(getSignInKey())
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);

        List<String> tokenRoles = extractRoles(token);
        List<String> userRoles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return (username.equals(userDetails.getUsername()))
                && new HashSet<>(tokenRoles).containsAll(userRoles)
                && !isTokenExpired(token);
    }

    private Claims extractAllClaims(String token) throws JwtException {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("roles", List.class);
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}