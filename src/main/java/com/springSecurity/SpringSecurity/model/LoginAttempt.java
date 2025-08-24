package com.springSecurity.SpringSecurity.model;


import java.time.Instant;
import jakarta.persistence.*;
import lombok.*;

@Getter @Setter
@Entity @Table(name="login_attempts", indexes = {
  @Index(name="idx_login_attempt_ts", columnList = "timestamp"),
  @Index(name="idx_login_attempt_username", columnList = "username")
})
public class LoginAttempt {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Instant timestamp = Instant.now();

    @Column(length=80, nullable=false)
    private String username;

    private boolean success;
    @Column(length=120)
    private String reason; 

    private String ip;
    private String userAgent;
}