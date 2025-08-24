package com.springSecurity.SpringSecurity.exceptions;

public class UserAlreadyExistsException extends BusinessException {
    public UserAlreadyExistsException(String username) {
        super("USER_ALREADY_EXISTS", "Usuário já existe: " + username);
    }
}
