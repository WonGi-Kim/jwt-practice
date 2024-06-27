package com.wongi.jwt_practice.dto;

import lombok.Getter;

@Getter
public class TokenRefreshRequestDto {
    private String refreshToken;
}
