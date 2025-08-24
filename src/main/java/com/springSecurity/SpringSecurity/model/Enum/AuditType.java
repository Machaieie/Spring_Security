package com.springSecurity.SpringSecurity.model.Enum;

public enum AuditType {
    LOGIN_ATTEMPT, LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT,
    ACCESS_DENIED, TOKEN_REFRESH, USER_CREATED, USER_STATE_CHANGED
}
