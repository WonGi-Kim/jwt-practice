package com.wongi.jwt_practice.controller;

import com.wongi.jwt_practice.dto.LoginResponseDto;
import com.wongi.jwt_practice.dto.TokenRefreshRequestDto;
import com.wongi.jwt_practice.dto.UserloginReqeustDto;
import com.wongi.jwt_practice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody UserloginReqeustDto userloginReqeustDto) {
        return ResponseEntity.ok(authService.signup(userloginReqeustDto));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody UserloginReqeustDto reqeustDto) {
        return authService.authenticate(reqeustDto.getUsername(), reqeustDto.getPassword());
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody TokenRefreshRequestDto requestDto) {
        return ResponseEntity.ok(authService.refreshToken(requestDto.getRefreshToken()));
    }
}
