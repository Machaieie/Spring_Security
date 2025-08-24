package com.springSecurity.SpringSecurity.model.Enum;

public enum AuditType {
    // Autenticação
    LOGIN_ATTEMPT,
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,
    TOKEN_REFRESH,
    ACCESS_DENIED,

    // Usuário
    USER_CREATED,
    USER_UPDATED,
    USER_DELETED,
    USER_STATE_CHANGED,
    USER_BLOCKED,
    USER_UNBLOCKED,
    USER_SUSPENDED,
    USER_REACTIVATED,
    USER_EXISTING, // tentativa de criação de usuário já existente

    // Email e PIN/Senha
    EMAIL_VERIFIED,
    EMAIL_CHANGED,
    EMAIL_NOT_FOUND,
    PIN_RESET,
    EMAIL_EXISTING,
    PASSWORD_RESET,
    PASSWORD_CHANGED,

    // Segurança
    MULTIPLE_FAILED_ATTEMPTS,
    ACCOUNT_LOCKED,
    ACCOUNT_UNLOCKED, USER_NOT_FOUND
}
