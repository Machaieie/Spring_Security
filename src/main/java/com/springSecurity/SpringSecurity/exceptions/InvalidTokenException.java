package com.springSecurity.SpringSecurity.exceptions;

public class InvalidTokenException extends BusinessException {
    public InvalidTokenException(String token) {
        super("INVALID_TOKEN", "Token inválido ou expirado: " + token);
    }
}
