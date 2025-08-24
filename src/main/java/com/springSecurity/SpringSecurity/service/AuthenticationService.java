package com.springSecurity.SpringSecurity.service;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.springSecurity.SpringSecurity.aspectJ.LogAction;
import com.springSecurity.SpringSecurity.model.Enum.AuditType;
import com.springSecurity.SpringSecurity.exceptions.EmailAlreadyExistsException;
import com.springSecurity.SpringSecurity.exceptions.UserAlreadyExistsException;
import com.springSecurity.SpringSecurity.model.User;
import com.springSecurity.SpringSecurity.model.DTO.request.RegisterRequestDTO;
import com.springSecurity.SpringSecurity.model.DTO.response.AuthenticationResponse;
import com.springSecurity.SpringSecurity.model.Enum.Role;
import com.springSecurity.SpringSecurity.model.Enum.UserState;
import com.springSecurity.SpringSecurity.repository.UserRepository;
import com.springSecurity.SpringSecurity.security.EmailHash;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Value("${app.email.hash.pepper}")
    private String emailHashPepper;

    @Transactional
    @LogAction(type = AuditType.USER_CREATED, details = "User registration")
    public AuthenticationResponse register(RegisterRequestDTO request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new UserAlreadyExistsException(request.username());
        }

        String emailHash = EmailHash.hmacSha256Hex(request.email(), emailHashPepper);
        if (userRepository.existsByEmailHash(emailHash)) {
            throw new EmailAlreadyExistsException("Email already registered");
        }

        User user = new User();
        user.setUsername(request.username());
        user.setPassword(passwordEncoder.encode(request.password())); 
        user.setEmail(request.email());         
        user.setEmailHash(emailHash);           
        user.setRole(request.role() != null ? request.role() : Role.EMPLOYEE);
        user.setUserState(UserState.ACTIVE);
        user.setFailedLoginCount(0);
        user.setMfaEnabled(false);
        user.setLastLoginAt(null);

        user = userRepository.save(user);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return new AuthenticationResponse(
            accessToken,
            refreshToken,
            "User registered successfully"
        );
    }
}
