package com.wildcodeschool.springsecurityworkshop.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.wildcodeschool.springsecurityworkshop.entity.User;
import com.wildcodeschool.springsecurityworkshop.repository.UserRepository;
import com.wildcodeschool.springsecurityworkshop.security.UserDetailsImpl;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
	@Autowired
	UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
		
		return UserDetailsImpl.build(user);
	}
}
