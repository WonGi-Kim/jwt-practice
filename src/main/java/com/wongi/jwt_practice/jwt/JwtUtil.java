package com.wongi.jwt_practice.jwt;

import com.wongi.jwt_practice.config.JwtConfig;
import com.wongi.jwt_practice.security.UserDetailsImpl;
import com.wongi.jwt_practice.util.RedisUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {
    private final long tokenExpiration;
    private final long refreshTokenExpiration;
    private final SecretKey secretKey;
    private final RedisUtil redisUtil;

    public JwtUtil(JwtConfig jwtConfig, RedisUtil redisUtil) {
        this.tokenExpiration = jwtConfig.getTokenExpiration();
        this.refreshTokenExpiration = jwtConfig.getRefreshTokenExpiration();
        this.secretKey = Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes());
        this.redisUtil = redisUtil;
    }

    public String createAccessToken(String username) {
        return generateToken(username, tokenExpiration);
    }

    public String createRefreshToken(String username) {
        return generateToken((username), refreshTokenExpiration);
    }

    public String createAccessTokenFromRefresh(String refreshToken) {
        if (validateToken(refreshToken)) {
            String username = getUsernameFromToken(refreshToken);
            return createAccessToken(username);
        }
        throw new IllegalArgumentException("Refresh토큰이 유효하지 않음");
    }

    // 토큰 생성
    public String generateToken(String username, long expiration) {
        return Jwts.builder()
                .setSubject(username) // 토큰 발행 주체
                .setIssuedAt(new Date()) // 토큰 발행 시간
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // 토큰 만료 시간
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // 토큰 유효성 검사 : claims와 userDetails 비교
    public boolean validateToken(String token, UserDetailsImpl userDetails) {
        try {
            if(redisUtil.hasKeyBlackList(token)) {
                throw new RuntimeException("로그아웃 한 토큰");
            }
            String username = getUsernameFromToken(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }
    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            if(redisUtil.hasKeyBlackList(token)) {
                throw new RuntimeException("로그아웃 한 토큰");
            }
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    // JWT 토큰에서 Claims 추출 (사용자 정보)
    private Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Bearer 제거하고 token 보내기
    public String getUsernameFromToken(String token) {
        return extractClaims(token).getSubject();
    }

    // 토큰 만료일 cliam추출
    private boolean isTokenExpired(String token) {
        Date expiration = extractClaims(token).getExpiration();
        return expiration.before(new Date());
    }

    // 블랙리스트에 토큰 추가
    public void blacklistToken(String token) {
        long expirationMillis = calculateExpirationMillis();
        redisUtil.setBlackList(token, token, expirationMillis);
    }

    // 블랙리스트에서 토큰 검증
    public boolean isTokenBlacklisted(String token) {
        return redisUtil.hasKeyBlackList(token);
    }

    // 블랙리스트에서 토큰 제거
    public void removeTokenFromBlacklist(String token) {
        redisUtil.deleteBlackList(token);
    }

    // 유효하지 않은 토큰 예외 처리
    private void handleInvalidTokenException(Exception e) {
        throw new IllegalArgumentException("Invalid token: " + e.getMessage());
    }

    // 만료 시간 계산
    private long calculateExpirationMillis() {
        return refreshTokenExpiration * 1000; // Convert seconds to milliseconds
    }
}
