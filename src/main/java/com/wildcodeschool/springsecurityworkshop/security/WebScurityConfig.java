package com.wildcodeschool.springsecurityworkshop.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.wildcodeschool.springsecurityworkshop.service.UserDetailsServiceImpl;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebScurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	UserDetailsServiceImpl userDetailsService;
	
	@Bean
	public AuthFilterToken getAuthFilterToken() {
		return new AuthFilterToken();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//csrf : génére des tokens pour l'envoie de form. ici, on le disable
		http.cors().and().csrf().disable().authorizeHttpRequests()
			.antMatchers("/auth").permitAll()
			.antMatchers("/admin").hasRole("ROLE_ADMIN")
			.antMatchers("/articles").permitAll()
//			.antMatchers("/user").authenticated()
//			.anyRequest().authenticated()
			;
		
		http.addFilterBefore(getAuthFilterToken(), UsernamePasswordAuthenticationFilter.class);
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//on donne à notre auth le service qui va récupérer notre user et config un encodeur pour le password
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncode());
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		// TODO Auto-generated method stub
		return super.authenticationManagerBean();
	}
	
	@Bean //bean car pas de constructor. Grâce à bean, Spring va créer facilement une instance
	public PasswordEncoder passwordEncode() {
		return new BCryptPasswordEncoder();
	}
	
}
