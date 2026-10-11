package com.example.security_log_system.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class AuthRequestDto {

    @NotBlank(message = "username is required.")
    private String username;

    @NotBlank(message = "password is required.")
    private String password;
}
