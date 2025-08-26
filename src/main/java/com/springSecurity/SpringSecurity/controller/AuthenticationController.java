package com.springSecurity.SpringSecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.springSecurity.SpringSecurity.model.DTO.request.AuthenticationRequest;
import com.springSecurity.SpringSecurity.model.DTO.request.RegisterRequestDTO;
import com.springSecurity.SpringSecurity.model.DTO.response.AuthenticationResponse;
import com.springSecurity.SpringSecurity.service.AuthenticationService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegisterRequestDTO dto) {
        return ResponseEntity.ok(authenticationService.register(dto));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody AuthenticationRequest request,
            HttpServletRequest httpRequest
    ) {
        AuthenticationResponse response = authenticationService.authenticate(request, httpRequest);
        return ResponseEntity.ok(response);
    }

    // @PostMapping("/refresh-token")
    // public ResponseEntity<AuthenticationResponse> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO dto) {
    //     return ResponseEntity.ok(authenticationService.refreshToken(dto));
    // }

    // @PostMapping("/logout")
    // public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
    //     authenticationService.logout(authHeader);
    //     return ResponseEntity.ok("User logged out successfully.");
    // }
}
