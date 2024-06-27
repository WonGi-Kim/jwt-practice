package com.wongi.jwt_practice.dto;

public class AuthResponseDto {
    private String jwt;

    public AuthResponseDto(String jwt) {
        this.jwt = jwt;
    }

}
