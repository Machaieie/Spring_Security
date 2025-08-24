package com.springSecurity.SpringSecurity.model;

import java.time.Instant;
import java.time.LocalDateTime;

import com.springSecurity.SpringSecurity.model.Enum.AttemptStatus;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@Entity
@Table(name = "login_attempts", indexes = {
        @Index(name = "idx_login_attempt_ts", columnList = "timestamp"),
        @Index(name = "idx_login_attempt_username", columnList = "username")
})
public class LoginAttempt {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "attempt_id")
    private Long attemptId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "attempt_status", nullable = false)
    private AttemptStatus status;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "device_info")
    private String deviceInfo;

    @Column(name = "attempted_at")
    private LocalDateTime attemptedAt = LocalDateTime.now();
}