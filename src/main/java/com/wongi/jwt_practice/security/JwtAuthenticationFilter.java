package com.wongi.jwt_practice.security;

import com.wongi.jwt_practice.jwt.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j(topic ="JWT 인증")
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String token = null;

        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            log.info("토큰 유효성 검증");
            log.info("authorizationHeader :"+authorizationHeader);
            token = authorizationHeader.substring(7);
            // 블랙리스트 토큰인지 검사
            if (jwtUtil.isTokenBlacklisted(token)) {
                log.info("블랙 리스트 토큰");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            username = jwtUtil.getUsernameFromToken(token);
            log.info("username : "+username);
        }

        log.info("사용자 정보 검증");
        // 사용자 이름 존재, 현재 SecurityContextHolder에 인증 정보가 없는 경우
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetailsImpl userDetailsImpl = this.userDetailsService.loadUserByUsername(username);

            log.info("토큰 유효성 재 검증");
            if(jwtUtil.validateToken(token,userDetailsImpl)){
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetailsImpl,null,userDetailsImpl.getAuthorities()
                        );
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        log.info("인증 성공");
        filterChain.doFilter(request,response);
    }
}
