package com.springSecurity.SpringSecurity.service;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.springSecurity.SpringSecurity.model.User;
import com.springSecurity.SpringSecurity.model.Enum.AttemptStatus;
import com.springSecurity.SpringSecurity.model.Enum.AuditType;
import com.springSecurity.SpringSecurity.model.audit.LoginAttempt;
import com.springSecurity.SpringSecurity.repository.LoginAttemptRepository;

@Service
public class AuditService {

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

    // Logs login attempts
    public void logLoginAttempt(User user, AttemptStatus status, String ipAddress, String deviceInfo) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUser(user);
        attempt.setStatus(status);
        attempt.setIpAddress(ipAddress);
        attempt.setDeviceInfo(deviceInfo);
        attempt.setAttemptedAt(LocalDateTime.now());
        loginAttemptRepository.save(attempt);
    }

    public void logEvent(User user, AuditType type, String details) {
        System.out.printf("[AUDIT] User=%s | Type=%s | Details=%s%n",
                user != null ? user.getUsername() : "N/A", type, details);
    }
}
