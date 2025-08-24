package com.springSecurity.SpringSecurity.exceptions;

public class EmailAlreadyExistsException  extends BusinessException{

    public EmailAlreadyExistsException( String message) {
        super("USER_WITH_THIS_EMAIL_ALREADY_EXISTS",  message);       
    }
    
}
