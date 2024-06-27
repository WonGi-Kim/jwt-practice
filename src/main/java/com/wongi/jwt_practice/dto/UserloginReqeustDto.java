package com.wongi.jwt_practice.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class UserloginReqeustDto {
    private String username;
    private String password;
}
