package com.example.day2jwt.controller;

import org.springframework.web.bind.annotation.*;

import com.example.day2jwt.JwtService;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtService jwtService;

    public AuthController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody Map<String, String> request) {
        String username = request.get("username");

        // in real project: validate username + password here
        String token = jwtService.generateToken(username);

        return Map.of("token", token);
    }
}

