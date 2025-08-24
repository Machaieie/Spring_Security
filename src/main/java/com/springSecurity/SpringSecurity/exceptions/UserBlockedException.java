package com.springSecurity.SpringSecurity.exceptions;

public class UserBlockedException extends BusinessException{

    public UserBlockedException( String message) {
        super("USER_BLOCKED", message);
        
    }
    
}
