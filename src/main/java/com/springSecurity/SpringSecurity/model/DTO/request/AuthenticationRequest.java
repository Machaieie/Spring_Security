package com.springSecurity.SpringSecurity.model.DTO.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthenticationRequest(
        @NotBlank(message = "Username is required") 
        @Size(min = 4, max = 80) 
        String username,

        @NotBlank(message = "Password is required") 
        @Size(min = 6, max = 100) 
        String password
        ) {

}
