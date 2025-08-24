package com.springSecurity.SpringSecurity.exceptions;

public class AuthorizationException extends BusinessException {
    public AuthorizationException(String message) {
        super("AUTHZ_ERROR", message);
    }
}
