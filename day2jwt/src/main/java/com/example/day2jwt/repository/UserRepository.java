package com.example.day2jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.day2jwt.entity.UserEntity;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByUsername(String username);
}
