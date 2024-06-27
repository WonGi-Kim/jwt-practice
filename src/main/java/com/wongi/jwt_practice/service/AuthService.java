package com.wongi.jwt_practice.service;

import com.wongi.jwt_practice.dto.LoginResponseDto;
import com.wongi.jwt_practice.dto.UserloginReqeustDto;
import com.wongi.jwt_practice.entity.User;
import com.wongi.jwt_practice.entity.UserRoleEnum;
import com.wongi.jwt_practice.error.TokenExpiredException;
import com.wongi.jwt_practice.jwt.JwtUtil;
import com.wongi.jwt_practice.repository.UserRepository;
import com.wongi.jwt_practice.util.RedisUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.InputMismatchException;


@Service
@RequiredArgsConstructor
@Slf4j(topic = "service 로그 확인")
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;

    public ResponseEntity<LoginResponseDto> authenticate(String username, String password) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new IllegalArgumentException("유저 없음"));
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new InputMismatchException("비번 다름");
        }

        String accessToken = jwtUtil.createAccessToken(user.getUsername());
        String refreshToken = jwtUtil.createRefreshToken(user.getUsername());
        user.updateRefreshToken(refreshToken);
        userRepository.save(user);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.set("Refresh-Token", refreshToken);

        LoginResponseDto responseDto = new LoginResponseDto(user.getId(), user.getUsername());

        log.info("Returning response with headers: {}", headers);

        return new ResponseEntity<>(responseDto,headers, HttpStatus.OK);

        //return responseDto;

    }

    public String refreshToken(String refreshToken) {

        if (!jwtUtil.validateToken(refreshToken)) {
            throw new IllegalArgumentException("INVALID_TOKEN");
        }


        String username = jwtUtil.getUsernameFromToken(refreshToken);
        User user = userRepository.findByUsername(username).orElse(null);

        if (user == null) {
            throw new IllegalArgumentException("USER_NOT_FOUND");
        }

        // AccessToken 재발급
        String newAccessToken = jwtUtil.createAccessToken(username);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + newAccessToken);

        return refreshToken;
    }

    public LoginResponseDto signup(UserloginReqeustDto userloginReqeustDto) {
        String username = userloginReqeustDto.getUsername();
        String password = userloginReqeustDto.getPassword();

        String encodePassword = passwordEncoder.encode(password);

        User user = new User(username,encodePassword, UserRoleEnum.ADMIN);

        User savedUser = userRepository.save(user);

        return new  LoginResponseDto(savedUser.getId(), savedUser.getUsername());
    }

    public String logout(String tokenHeader) {
        try {
            String token = tokenHeader.substring(7);

            if (!jwtUtil.validateToken(token)) {
                throw new TokenExpiredException("Token expired or invalid");
            }
            jwtUtil.blacklistToken(token);
            if(jwtUtil.isTokenBlacklisted(token)) {
                return "Logout success";
            } else {
                throw new IllegalStateException("Failed to blacklist token");
            }
        } catch (Exception e) {
            log.error("Error during logout: {}", e.getMessage());

            throw new IllegalArgumentException("Failed to logout");
        }
    }

    public boolean checkToken(String tokenHeader) {
        String token = tokenHeader.substring(7);
        return !jwtUtil.validateToken(token);
    }

}
