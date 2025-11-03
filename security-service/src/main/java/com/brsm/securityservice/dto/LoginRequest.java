package com.brsm.securityservice.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String login;
    private String password;
}
