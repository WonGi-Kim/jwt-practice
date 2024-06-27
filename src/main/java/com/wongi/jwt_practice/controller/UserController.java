package com.wongi.jwt_practice.controller;

import com.wongi.jwt_practice.dto.LoginResponseDto;
import com.wongi.jwt_practice.dto.TokenRefreshRequestDto;
import com.wongi.jwt_practice.dto.UserloginReqeustDto;
import com.wongi.jwt_practice.error.TokenExpiredException;
import com.wongi.jwt_practice.security.UserDetailsImpl;
import com.wongi.jwt_practice.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j(topic = "로그아웃 검증용")
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

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String tokenHeader) {
        return ResponseEntity.ok(authService.logout(tokenHeader));
    }

    // 만료된 토큰 검증 엔드포인트
    @GetMapping("/check")
    public ResponseEntity<String> validateExpiredToken(@RequestHeader("Authorization") String tokenHeader) {
        try {
            boolean isExpired; // jwtUtil.checkToken(token);
            isExpired = authService.checkToken(tokenHeader);
            if (isExpired) {
                return ResponseEntity.ok("토큰이 만료 되었음");
            } else {
                return ResponseEntity.ok("토큰 유효함");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid token");
        }
    }
}
