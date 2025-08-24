package com.springSecurity.SpringSecurity.model.DTO.request;
import com.springSecurity.SpringSecurity.model.Enum.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record RegisterRequestDTO(
    @NotBlank(message = "Username is required")
    @Size(min = 4, max = 80)
    String username,

    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 100)
    String password,

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email")
    String email,
    @NotNull(message = "Role is required")
    Role role
) {}
