package com.wongi.jwt_practice.config;

import com.wongi.jwt_practice.security.JwtAuthenticationFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // H2 Console과 SpringSecurity 사용하기 위해서
    @Bean
    @ConditionalOnProperty(name = "spring.h2.console.enabled", havingValue = "true")
    public WebSecurityCustomizer corsCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toH2Console());
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {

        // CSRF 설정
        http.csrf((csrf) -> csrf.disable())
                .sessionManagement((sessionManagement) -> sessionManagement.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS)) // 세션 관리를 satateless로 설정
                .authorizeHttpRequests((authorizeHttpRequest) ->
                        authorizeHttpRequest
                                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                                .permitAll() // resource접근 허용
                                .requestMatchers("/", "api/auth/**").permitAll()
                                .requestMatchers(HttpMethod.GET, "/**").permitAll()
                                .requestMatchers("/h2-console/**").permitAll()
                                .anyRequest().permitAll() // 일단 모든 요청 허용
                );

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
