package com.springSecurity.SpringSecurity.model.DTO.response;

public record AuthenticationResponse(
    String accessToken,
    String refreshToken,
    String message
) {

    
}
