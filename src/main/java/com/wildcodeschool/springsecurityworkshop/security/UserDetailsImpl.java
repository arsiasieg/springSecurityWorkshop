package com.wildcodeschool.springsecurityworkshop.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.wildcodeschool.springsecurityworkshop.entity.Role;
import com.wildcodeschool.springsecurityworkshop.entity.User;

@Service
public class UserDetailsImpl implements UserDetails {
	
	private Long id;
	
	private String username;
	
	private String password;
	
	private String email;
	
	private List<SimpleGrantedAuthority> authorities; // = roles de user
	
	//Construction d'un UserDetailsImpl à partir des infos de l'user
	public static UserDetailsImpl build(User user) {
		UserDetailsImpl userDetailsImpl = new UserDetailsImpl();
		userDetailsImpl.setId(user.getId());
		userDetailsImpl.setUsername(user.getUsername());
		userDetailsImpl.setPassword(user.getPassword());
		userDetailsImpl.setEmail(user.getEmail());
		
		//Liste d'authorité simplifié (= rôles présents dans user)
		List<SimpleGrantedAuthority> simpleGrantedAuthorities = new ArrayList<>();
		for(Role role : user.getRoles()) {
			simpleGrantedAuthorities.add(new SimpleGrantedAuthority(role.getName().name()));
		}
		userDetailsImpl.setAuthorities(simpleGrantedAuthorities);
		return userDetailsImpl;
	}
	
	
	@Override
	public List<SimpleGrantedAuthority> getAuthorities() {
		return authorities;
	}
	
	@Override
	public String getPassword() {
		return password;
	}
	
	@Override
	public String getUsername() {
		return username;
	}
	
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}
	
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}
	
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	
	@Override
	public boolean isEnabled() {
		return true;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setAuthorities(List<SimpleGrantedAuthority> authorities) {
		this.authorities = authorities;
	}
	
}
