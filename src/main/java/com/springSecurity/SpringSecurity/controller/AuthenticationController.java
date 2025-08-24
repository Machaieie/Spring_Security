package com.springSecurity.SpringSecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.springSecurity.SpringSecurity.model.DTO.request.RegisterRequestDTO;
import com.springSecurity.SpringSecurity.model.DTO.response.AuthenticationResponse;
import com.springSecurity.SpringSecurity.service.AuthenticationService;

import jakarta.validation.Valid;

@Controller
@RequestMapping("api/auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegisterRequestDTO dto) {
        return ResponseEntity.ok(authenticationService.register(dto));
    }

}
