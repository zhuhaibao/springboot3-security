package com.jumper.oauth2.model;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}
