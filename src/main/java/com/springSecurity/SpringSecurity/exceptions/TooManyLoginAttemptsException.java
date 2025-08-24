package com.springSecurity.SpringSecurity.exceptions;

public class TooManyLoginAttemptsException extends BusinessException {
    public TooManyLoginAttemptsException(String username) {
        super("LOGIN_RATE_LIMIT", "Muitas tentativas falhadas para o usuário: " + username);
    }
}
