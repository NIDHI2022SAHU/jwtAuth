package com.example.day2jwt.model;

import lombok.Data;

@Data
public class AuthRequest {
    private String username;
    private String password; // optional for now, can validate later
}
