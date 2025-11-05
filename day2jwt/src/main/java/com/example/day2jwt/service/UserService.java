package com.example.day2jwt.service;

import com.example.day2jwt.entity.UserEntity;
import com.example.day2jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    // Signup: save user in DB
    public UserEntity signup(String username, String password) {
        logger.info("Signup attempt for username: {}", username);

        if (userRepository.findByUsername(username).isPresent()) {
            logger.warn("Username '{}' already exists", username);
            throw new RuntimeException("Username already exists");
        }

        UserEntity user = UserEntity.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .build();

        UserEntity savedUser = userRepository.save(user);
        logger.info("User '{}' registered successfully with ID {}", username, savedUser.getId());

        return savedUser;
    }

    // Fetch user by username
    public UserEntity getByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    // Validate raw password with encoded password
    public boolean validatePassword(UserEntity user, String rawPassword) {
        boolean matches = passwordEncoder.matches(rawPassword, user.getPassword());
        logger.info("Password validation for user '{}': {}", user.getUsername(), matches ? "SUCCESS" : "FAILURE");
        return matches;
    }
}
