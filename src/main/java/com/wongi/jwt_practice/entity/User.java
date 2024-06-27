package com.wongi.jwt_practice.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;

    @Column(length = 1000)
    private String refreshToken;

    @Column(nullable = false)
    @Enumerated(value = EnumType.STRING)
    private UserRoleEnum userRole;

    public User(String username, String password, UserRoleEnum userRole) {
        this.username = username;
        this.password = password;
        this.userRole = userRole;
    }
    public void updateRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void setUserRole(UserRoleEnum userRole) {
        this.userRole = userRole;
    }

}
