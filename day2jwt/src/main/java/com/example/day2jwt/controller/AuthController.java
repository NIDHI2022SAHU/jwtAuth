package com.example.day2jwt.controller;

import com.example.day2jwt.dto.AuthRequestDTO;
import com.example.day2jwt.dto.AuthResponseDTO;
import com.example.day2jwt.entity.UserEntity;
import com.example.day2jwt.service.JwtService;
import com.example.day2jwt.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    // Signup: only register user
    @PostMapping("/signup")
    public AuthResponseDTO signup(@RequestBody @Valid AuthRequestDTO request) {
        userService.signup(request.getUsername(), request.getPassword());
        return new AuthResponseDTO(null, "User registered successfully");
    }

    // Login: check credentials and generate token
    @PostMapping("/login")
    public AuthResponseDTO login(@RequestBody @Valid AuthRequestDTO request) {
        UserEntity user = userService.getByUsername(request.getUsername());

        if (!userService.validatePassword(user, request.getPassword())) {
            logger.warn("Login failed for username: {} (invalid password)", request.getUsername());
            throw new RuntimeException("Invalid credentials");
        }

        String token = jwtService.generateToken(user.getUsername());
        logger.info("User '{}' logged in successfully", user.getUsername());

        return new AuthResponseDTO(token, "Login successful");
    }
}
