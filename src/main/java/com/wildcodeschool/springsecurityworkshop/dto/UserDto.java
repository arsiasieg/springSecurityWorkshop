package com.wildcodeschool.springsecurityworkshop.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class UserDto {
	
	@NotBlank
	@Size(min = 4, max = 50)
	private String username;
	
	@NotBlank
	@Email
	@Size(min = 4, max = 100)
	private String email;
	
	@NotBlank
	@Size(min = 8, max = 20)
	private String password;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	
}
