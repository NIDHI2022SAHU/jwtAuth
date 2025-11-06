package com.example.day2jwt.controller;

import com.example.day2jwt.dto.ApiResponse;
import com.example.day2jwt.dto.UserRequestDTO;
import com.example.day2jwt.dto.UserResponseDTO;
import com.example.day2jwt.entity.UserEntity;
import com.example.day2jwt.service.JwtService;
import com.example.day2jwt.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final JwtService jwtService;

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    /**
     * Signup endpoint — register new user
     */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<UserResponseDTO>> signup(@RequestBody @Valid UserRequestDTO request) {
        userService.signup(request);

        ApiResponse<UserResponseDTO> response = new ApiResponse<>(
                HttpStatus.CREATED.value(),
                "User registered successfully",
                new UserResponseDTO(request.getUsername(), null),
                "Login to continue");

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Login endpoint — validate credentials & return JWT token
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<UserResponseDTO>> login(@RequestBody @Valid UserRequestDTO request) {
        UserEntity user = userService.getByUsername(request.getUsername());

        if (!userService.validatePassword(user, request.getPassword())) {
            logger.warn("Login failed for username: {} (invalid password)", request.getUsername());
            throw new RuntimeException("Invalid credentials");
        }

        String token = jwtService.generateToken(user.getUsername());
        logger.info("User '{}' logged in successfully", user.getUsername());

        ApiResponse<UserResponseDTO> response = new ApiResponse<>(
                HttpStatus.OK.value(),
                "Login successful",
                new UserResponseDTO(token, user.getUsername()),
                "");

        return ResponseEntity.ok(response);
    }

    /**
     * Logout endpoint — invalidate token by blacklisting it
     */
    // @PostMapping("/logout")
    // public ResponseEntity<ApiResponse<Void>>
    // logout(@RequestHeader("Authorization") String authHeader) {
    // String token = authHeader.substring(7);
    // jwtService.blacklistToken(token);

    // ApiResponse<Void> response = new ApiResponse<>(
    // HttpStatus.OK.value(),
    // "Logged out successfully",
    // null,
    // "Login Again!");

    // return ResponseEntity.ok(response);
    // }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7);
        String username = jwtService.extractUsername(token);

        userService.logout(username);

        ApiResponse<Void> response = new ApiResponse<>(
                HttpStatus.OK.value(),
                "Logged out successfully",
                null,
                "All previous tokens are now invalid");

        return ResponseEntity.ok(response);
    }

}
