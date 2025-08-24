package com.springSecurity.SpringSecurity.exceptions;

public class CryptoException extends BusinessException {
    public CryptoException(String message, Throwable cause) {
        super("CRYPTO_ERROR", message);
        initCause(cause);
    }
}
