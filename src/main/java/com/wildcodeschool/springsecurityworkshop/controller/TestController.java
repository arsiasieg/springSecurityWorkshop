package com.wildcodeschool.springsecurityworkshop.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
@RequestMapping("/test")
public class TestController {

	@GetMapping("/admin")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	public String sayHelloAdmin() {
		return "Hello, you are the best admin ever !";
	}
	
	@GetMapping
	@PreAuthorize("hasRole('ROLE_USER')")
	public String sayHelloUser() {
		return "Hello, poor user !";
	}
}
