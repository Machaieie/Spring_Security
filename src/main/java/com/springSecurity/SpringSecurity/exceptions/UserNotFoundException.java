package com.springSecurity.SpringSecurity.exceptions;

public class UserNotFoundException extends BusinessException {
    public UserNotFoundException(String username) {
        super("USER_NOT_FOUND", "Usuário não encontrado: " + username);
    }
}