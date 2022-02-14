package com.wildcodeschool.springsecurityworkshop.controller;

import java.util.ArrayList;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.wildcodeschool.springsecurityworkshop.dto.AuthResponseDto;
import com.wildcodeschool.springsecurityworkshop.dto.UserAuthDto;
import com.wildcodeschool.springsecurityworkshop.dto.UserDto;
import com.wildcodeschool.springsecurityworkshop.entity.ERole;
import com.wildcodeschool.springsecurityworkshop.entity.Role;
import com.wildcodeschool.springsecurityworkshop.entity.User;
import com.wildcodeschool.springsecurityworkshop.repository.RoleRepository;
import com.wildcodeschool.springsecurityworkshop.repository.UserRepository;
import com.wildcodeschool.springsecurityworkshop.security.JWTUtils;
import com.wildcodeschool.springsecurityworkshop.security.UserDetailsImpl;

@RestController
@CrossOrigin
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	UserRepository userRepository;
	
	@Autowired
	RoleRepository roleRepository;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	JWTUtils jwtUtils;

	@PostMapping("/signup")
	public void registerUser(@Valid @RequestBody UserDto userDto) {
		// On vérifie que les données du user ne sont pas dans la BDD
		if (userRepository.existsByUsername(userDto.getUsername())
				|| userRepository.existsByEmail(userDto.getEmail())) {
			throw new ResponseStatusException(HttpStatus.CONFLICT);
		}
		
		//Création du user avec les datas du DTO
		User user = new User();
		user.setUsername(userDto.getUsername());
		user.setEmail(userDto.getEmail());
		//On utilise l'encodeur fournis par le bean dans WebSecurityConfig
		user.setPassword(passwordEncoder.encode(userDto.getPassword()));
		
		//On va cherche le role user pour le mettre à chaque personne qui s'enregistre
		Role role = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
		//On doit associer une liste de rôle au user donc on en créée une et on met le rôle user dedans
		List<Role> roles = new ArrayList<Role>();
		roles.add(role);
		user.setRoles(roles);
		//On save le user (avec toutes les données en place) dans la BDD
		userRepository.save(user);
	}
	
	@PostMapping("/signin")
	public AuthResponseDto authentUser(@Valid @RequestBody UserAuthDto userAuthDto) {
		//Grâce à l'authenticationManager, on peut vérifier que le user/password existe et que le couple est correct
		Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userAuthDto.getUsername(), userAuthDto.getPassword()));
		
		// = userDetailsImpl (Spring l'a automatiquement contruit via l'auth)
	 	UserDetailsImpl userDetailsImpl = (UserDetailsImpl) auth.getPrincipal();
		
	 	
	 	//Récupération des roles à envoyer au front
	 	List<String> roles = new ArrayList<>();
	 	for(SimpleGrantedAuthority simpleGrantedAuthotority : userDetailsImpl.getAuthorities()) {
	 		roles.add(simpleGrantedAuthotority.getAuthority());
	 	}
	 	
	 	//on va récupérer le username et les roles pour les intégrer avec le token
	 	return new AuthResponseDto(userDetailsImpl.getUsername(), roles, jwtUtils.generateToken(userDetailsImpl));
	}
}
