package com.wongi.jwt_practice.dto;

import lombok.Getter;

@Getter
public class LoginResponseDto {
    private Long id;
    private String username;

    public LoginResponseDto(Long id, String username) {
        this.id = id;
        this.username = username;
    }
}
