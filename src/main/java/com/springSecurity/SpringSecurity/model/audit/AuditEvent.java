package com.springSecurity.SpringSecurity.model.audit;

import java.time.Instant;

import com.springSecurity.SpringSecurity.model.Enum.AuditSeverity;
import com.springSecurity.SpringSecurity.model.Enum.AuditType;

import jakarta.persistence.*;
import lombok.*;

@Getter @Setter
@Entity
@Table(name = "audit_events", indexes = {
    @Index(name="idx_audit_ts", columnList = "timestamp"),
    @Index(name="idx_audit_user", columnList = "userId")
})
public class AuditEvent {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Instant timestamp = Instant.now();

    private Long userId;
    private String username;
    private String ip;
    private String userAgent;

    @Enumerated(EnumType.STRING)
    @Column(length=40, nullable=false)
    private AuditType type;

    @Enumerated(EnumType.STRING)
    @Column(length=10, nullable=false)
    private AuditSeverity severity = AuditSeverity.INFO;

    @Column(length=2048)
    private String details;

    @Column(length=100)
    private String actionName; 
}
