package com.brsm.securityservice.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String login;
    private String password;
    private Integer studentId;
}
