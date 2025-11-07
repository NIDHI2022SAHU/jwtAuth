package com.example.day2jwt.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.example.day2jwt.entity.UserEntity;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long jwtAccessTokenExpirationMs;

    @Value("${jwt.refresh.expiration}")
    private Long jwtRefreshTokenExpirationMs;

    // Generate signing key
    private Key getSignKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    // Generate JWT token with optional claims
    public String generateAccessToken(String username, Map<String, Object> extraClaims) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .claim("type", "access")
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtAccessTokenExpirationMs))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(String username) {
        return generateAccessToken(username, Map.of());
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder()
                .claim("type", "refresh")
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtRefreshTokenExpirationMs))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Extract username (subject) from token
    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (ExpiredJwtException e) {
            return null;
        } catch (JwtException e) {
            return null;
        }
    }

    public Integer extractTokenVersion(String token) {
        Object version = parseToken(token).getBody().get("tokenVersion");
        return version != null ? Integer.parseInt(version.toString()) : 0;
    }

    // Extract expiration date from token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract any claim using a resolver function
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String extractTokenType(String token) {
        Claims claims = extractAllClaims(token);
        return (String) claims.get("type");
    }

    // Parse and validate token
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            throw new RuntimeException("Invalid or expired JWT token", e);
        }
    }

    public boolean isTokenValid(String token, UserEntity user) {
        final String extractedUsername = extractUsername(token);
        final Integer extractedVersion = extractTokenVersion(token);

        return extractedUsername.equals(user.getUsername())
                && extractedVersion.equals(user.getTokenVersion())
                && !isTokenExpired(token);
    }

    public boolean isRefreshTokenValid(String token, UserEntity user) {
        final String username = extractUsername(token);
        return (username != null && username.equals(user.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Jws<Claims> parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token);
    }
}
