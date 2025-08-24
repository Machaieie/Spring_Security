package com.springSecurity.SpringSecurity.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.springSecurity.SpringSecurity.exceptions.AuthenticationException;
import com.springSecurity.SpringSecurity.exceptions.AuthorizationException;
import com.springSecurity.SpringSecurity.exceptions.BusinessException;
import com.springSecurity.SpringSecurity.exceptions.CryptoException;
import com.springSecurity.SpringSecurity.exceptions.InvalidTokenException;
import com.springSecurity.SpringSecurity.exceptions.TooManyLoginAttemptsException;
import com.springSecurity.SpringSecurity.exceptions.UserAlreadyExistsException;
import com.springSecurity.SpringSecurity.exceptions.UserNotFoundException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<Map<String, Object>> handleBusinessException(BusinessException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("errorCode", ex.getCode());
        body.put("message", ex.getMessage());

        HttpStatus status = HttpStatus.BAD_REQUEST;

        if (ex instanceof AuthenticationException) {
            status = HttpStatus.UNAUTHORIZED;
        } else if (ex instanceof AuthorizationException) {
            status = HttpStatus.FORBIDDEN;
        } else if (ex instanceof UserNotFoundException) {
            status = HttpStatus.NOT_FOUND;
        } else if (ex instanceof UserAlreadyExistsException) {
            status = HttpStatus.CONFLICT;
        } else if (ex instanceof TooManyLoginAttemptsException) {
            status = HttpStatus.TOO_MANY_REQUESTS;
        } else if (ex instanceof InvalidTokenException) {
            status = HttpStatus.UNAUTHORIZED;
        } else if (ex instanceof CryptoException) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }

        return ResponseEntity.status(status).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("errorCode", "GENERIC_ERROR");
        body.put("message", ex.getMessage());

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}
