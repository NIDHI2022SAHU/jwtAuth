package com.example.day2jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class Day2jwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(Day2jwtApplication.class, args);
	}

}
