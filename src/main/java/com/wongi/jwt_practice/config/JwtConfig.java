package com.wongi.jwt_practice.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
public class JwtConfig {
    @Value("${spring.jwt.secret.key}")
    private String secretKey;

    @Value("${spring.jwt.token.expiration}")
    private long tokenExpiration;

    @Value("${spring.jwt.refresh.token.expiration}")
    private long refreshTokenExpiration;
}
