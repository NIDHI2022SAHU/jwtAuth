package com.example.day2jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.day2jwt.service.JwtService;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired
    private JwtService jwtService;

    // @GetMapping("/profile")
    // public Map<String, String> profile(@RequestHeader("Authorization") String
    // authHeader) {
    // return Map.of("message", "You are authorized!");
    // }

    @GetMapping("/profile")
    public ResponseEntity<Map<String, String>> profile(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.substring(7);
            String type = jwtService.extractTokenType(token);

            if (!"access".equals(type)) {
                return ResponseEntity.status(403).body(Map.of("error", "Use access token, not refresh token"));
            }

            String username = jwtService.extractUsername(token);
            if (username == null) {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid or expired token"));
            }

            return ResponseEntity.ok(Map.of("message", "Welcome " + username));

        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token or format"));
        }
    }

}
