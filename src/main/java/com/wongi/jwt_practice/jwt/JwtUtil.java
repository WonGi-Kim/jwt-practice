package com.wongi.jwt_practice.jwt;

import com.wongi.jwt_practice.config.JwtConfig;
import com.wongi.jwt_practice.security.UserDetailsImpl;
import io.jsonwebtoken.Claims;
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

    public JwtUtil(JwtConfig jwtConfig) {
        this.tokenExpiration = jwtConfig.getTokenExpiration();
        this.refreshTokenExpiration = jwtConfig.getRefreshTokenExpiration();
        this.secretKey = Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes());
    }

    public String createAccessToken(String username) {
        return generateToken(username, tokenExpiration);
    }

    public String createRefreshToken(String username) {
        return generateToken((username), refreshTokenExpiration);
    }

    public String createAccessTokenFromRefresh(String refreshToken) {

        if(validateToken(refreshToken)){
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


     //토큰 유효성 검사 : claims와 userDetails비교
    public boolean validateToken(String token, UserDetailsImpl userDetails) {
        try {
            String username = getUsernameFromToken(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }
    // 토큰 유효성 검사
    public boolean validateToken(String token){
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    // JWT 토큰에서 Claims추출 (사용자 정보)
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
}
