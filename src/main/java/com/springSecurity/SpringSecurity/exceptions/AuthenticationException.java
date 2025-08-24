package com.springSecurity.SpringSecurity.exceptions;

public class AuthenticationException extends BusinessException {
    public AuthenticationException(String message) {
        super("AUTH_ERROR", message);
    }
}