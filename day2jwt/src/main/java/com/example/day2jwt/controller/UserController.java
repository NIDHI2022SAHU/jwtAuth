package com.example.day2jwt.controller;

import com.example.day2jwt.dto.ApiResponse;
import com.example.day2jwt.dto.UserRequestDTO;
import com.example.day2jwt.dto.UserResponseDTO;
import com.example.day2jwt.entity.UserEntity;
import com.example.day2jwt.service.JwtService;
import com.example.day2jwt.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.util.Map;

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
                new UserResponseDTO(request.getUsername(), "", ""),
                "Login to continue");

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Login endpoint — validate credentials & return JWT token
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<UserResponseDTO>> login(@RequestBody @Valid UserRequestDTO request) {
        try {
            UserEntity user = userService.getByUsername(request.getUsername());

            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ApiResponse<>(401, "User not found", null, "Sign up first"));
            }

            if (!userService.validatePassword(user, request.getPassword())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ApiResponse<>(401, "Invalid credentials", null, "Check your password"));
            }

            String accessToken = jwtService.generateToken(user.getUsername());
            String refreshToken = jwtService.generateRefreshToken(user.getUsername());
            userService.saveRefreshToken(user.getUsername(), refreshToken);

            ApiResponse<UserResponseDTO> response = new ApiResponse<>(
                    HttpStatus.OK.value(),
                    "Login successful",
                    new UserResponseDTO(user.getUsername(), accessToken, refreshToken),
                    "");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Login error for user '{}': {}", request.getUsername(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Login failed: " + e.getMessage(), null, "Check server logs"));
        }
    }

    /**
     * Refresh token endpoint — issue new tokens
     * Supports two modes:
     * 1. Rotating (loop) mode — new refresh token generated every time.
     * 2. Fixed (7-day) mode — only new access token generated until refresh token
     * expires.
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<UserResponseDTO>> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        logger.info("Refresh token request received");

        // Extract username from refresh token
        String username = jwtService.extractUsername(refreshToken);

        // Validate refresh token with DB
        if (!userService.validateRefreshToken(username, refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(401, "Invalid or expired refresh token", null, "Login required"));
        }
        // Generate new access token
        String newAccessToken = jwtService.generateToken(username);

        // Decide whether to rotate refresh token or not
        boolean ROTATE_REFRESH_TOKENS = false; // Set true for loop mode, false for 7-day static mode

        String newRefreshToken = refreshToken; // Default: same token (static mode)
        String messageNote = "New access token generated using existing refresh token";

        if (ROTATE_REFRESH_TOKENS) {
            newRefreshToken = jwtService.generateRefreshToken(username);
            userService.saveRefreshToken(username, newRefreshToken); // Replace in DB
            messageNote = "New access and refresh tokens generated (rotation mode)";
        }

        ApiResponse<UserResponseDTO> response = new ApiResponse<>(
                HttpStatus.OK.value(),
                "Token refreshed successfully",
                new UserResponseDTO(username, newAccessToken, newRefreshToken),
                messageNote);

        return ResponseEntity.ok(response);
    }

    /**
     * Logout endpoint — invalidate existing tokens
     */

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
