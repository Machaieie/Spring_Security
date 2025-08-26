package com.springSecurity.SpringSecurity.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.springSecurity.SpringSecurity.aspectJ.LogAction;
import com.springSecurity.SpringSecurity.model.Enum.AttemptStatus;
import com.springSecurity.SpringSecurity.model.Enum.AuditType;
import com.springSecurity.SpringSecurity.exceptions.AuthenticationException;
import com.springSecurity.SpringSecurity.exceptions.EmailAlreadyExistsException;
import com.springSecurity.SpringSecurity.exceptions.UserAlreadyExistsException;
import com.springSecurity.SpringSecurity.exceptions.UserBlockedException;
import com.springSecurity.SpringSecurity.exceptions.UserNotFoundException;
import com.springSecurity.SpringSecurity.model.Token;
import com.springSecurity.SpringSecurity.model.User;
import com.springSecurity.SpringSecurity.model.DTO.request.AuthenticationRequest;
import com.springSecurity.SpringSecurity.model.DTO.request.RegisterRequestDTO;
import com.springSecurity.SpringSecurity.model.DTO.response.AuthenticationResponse;
import com.springSecurity.SpringSecurity.model.Enum.Role;
import com.springSecurity.SpringSecurity.model.Enum.UserState;
import com.springSecurity.SpringSecurity.repository.TokenRepository;
import com.springSecurity.SpringSecurity.repository.UserRepository;
import com.springSecurity.SpringSecurity.security.EmailHash;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private AuditService auditService;

    @Autowired
    private TokenRepository tokenRepository;

    @Value("${app.email.hash.pepper}")
    private String emailHashPepper;

    @Transactional
    @LogAction(type = AuditType.USER_CREATED, details = "User registration")
    public AuthenticationResponse register(RegisterRequestDTO request) {
        try {
            if (userRepository.existsByUsername(request.username())) {
                auditService.logEvent(null, AuditType.USER_EXISTING,
                        "Registration failed: Username already exists - " + request.username());
                throw new UserAlreadyExistsException(request.username());
            }

            String emailHash = EmailHash.hmacSha256Hex(request.email(), emailHashPepper);
            if (userRepository.existsByEmailHash(emailHash)) {
                auditService.logEvent(null, AuditType.EMAIL_EXISTING,
                        "Registration failed: Email already registered - " + request.email());
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

            auditService.logEvent(user, AuditType.USER_CREATED, "User registered successfully");

            return new AuthenticationResponse(
                    accessToken,
                    refreshToken,
                    "User registered successfully");

        } catch (RuntimeException ex) {
            auditService.logEvent(null, AuditType.ACCESS_DENIED,
                    "User registration failed: " + ex.getMessage());
            throw ex;
        }
    }

    @LogAction(type = AuditType.LOGIN_ATTEMPT, details = "User login attempt")
    public AuthenticationResponse authenticate(AuthenticationRequest loginRequestDTO, HttpServletRequest httpRequest) {
        boolean success = false;

        User user = userRepository.findByUsername(loginRequestDTO.username())
                .orElseThrow(() -> {
                    auditService.logEvent(null, AuditType.USER_NOT_FOUND,
                            "Login failed: User not found - " + loginRequestDTO.username());
                    return new UserNotFoundException("User not found");
                });

        if (user.isBlocked()) {
            auditService.logEvent(user, AuditType.USER_BLOCKED,
                    "Login blocked: User account is blocked");
            throw new UserBlockedException("Account is blocked due to multiple failed login attempts");
        }

        String ipAddress = httpRequest.getRemoteAddr();
        String deviceInfo = httpRequest.getHeader("User-Agent");

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequestDTO.username(), loginRequestDTO.password()));

            user.setFailedLoginCount(0);
            userRepository.save(user);

            success = true;

            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            revokeAllTokenByUser(user);
            saveUserToken(accessToken, refreshToken, user);

            auditService.logEvent(user, AuditType.LOGIN_SUCCESS, "User login successful");

            return new AuthenticationResponse(accessToken, refreshToken, "User login successful");

        } catch (BadCredentialsException ex) {
            int attempts = user.getFailedLoginCount() + 1;
            user.setFailedLoginCount(attempts);

            if (attempts >= 3) {
                user.setUserState(UserState.BLOCKED);
                auditService.logEvent(user, AuditType.ACCOUNT_LOCKED,
                        "User account locked due to multiple failed attempts");
            }

            userRepository.save(user);

            auditService.logEvent(user, AuditType.LOGIN_FAILURE, "Login failed: Invalid credentials");
            throw new AuthenticationException("Invalid username or password");

        } finally {
            auditService.logLoginAttempt(user,
                    success ? AttemptStatus.SUCCESS : AttemptStatus.FAILED,
                    ipAddress,
                    deviceInfo);
        }
    }

    private void revokeAllTokenByUser(User user) {
        List<Token> validTokens = tokenRepository.findAllAccessTokensByUser(user.getId());
        if (validTokens.isEmpty()) {
            return;
        }
        validTokens.forEach(t -> t.setLoggedOut(true));
        tokenRepository.saveAll(validTokens);
    }

    private void saveUserToken(String accessToken, String refreshToken, User user) {
        Token token = new Token();
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }

    public ResponseEntity refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            auditService.logEvent(null, AuditType.ACCESS_DENIED, "Token refresh denied: Missing Authorization header");
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        String username = jwtService.extractUsername(token);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    auditService.logEvent(null, AuditType.USER_NOT_FOUND,
                            "Token refresh denied: User not found - " + username);
                    return new RuntimeException("No user found");
                });

        if (jwtService.isValidRefreshToken(token, user)) {
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            revokeAllTokenByUser(user);
            saveUserToken(accessToken, refreshToken, user);

            auditService.logEvent(user, AuditType.TOKEN_REFRESH, "New token generated");

            return new ResponseEntity(new AuthenticationResponse(accessToken, refreshToken, "New token generated"),
                    HttpStatus.OK);
        }

        auditService.logEvent(user, AuditType.ACCESS_DENIED, "Token refresh failed: Invalid refresh token");
        return new ResponseEntity(HttpStatus.UNAUTHORIZED);
    }
}
