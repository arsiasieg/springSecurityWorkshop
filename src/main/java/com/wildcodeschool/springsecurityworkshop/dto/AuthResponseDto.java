package com.wildcodeschool.springsecurityworkshop.dto;

import java.util.List;

public class AuthResponseDto {

	private String username;
	private List<String> roles;
	private String jwtToken;

	public AuthResponseDto(String username, List<String> roles, String jwtToken) {
		this.username = username;
		this.roles = roles;
		this.jwtToken = jwtToken;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}

	public String getJwtToken() {
		return jwtToken;
	}

	public void setJwtToken(String jwtToken) {
		this.jwtToken = jwtToken;
	}

}
