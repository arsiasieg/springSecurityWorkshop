package com.wildcodeschool.springsecurityworkshop.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.wildcodeschool.springsecurityworkshop.service.UserDetailsServiceImpl;


public class AuthFilterToken extends OncePerRequestFilter {
	
	@Autowired
	JWTUtils jwtUtils;
	
	@Autowired
	UserDetailsServiceImpl userDetailsServiceImpl;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		// Vérifier si un token est présent
		String token = this.getTokenFromHeader(request);
		
		
		try {
			//Si le token n'est pas null et valide
			if(token != null && jwtUtils.isValidToken(token)) {
				//Décoder le token & récupérer le user
				String username = jwtUtils.getUsernameFromToken(token);
				
				//Comparer le user avec la DB (via le userDetailsImp)
				UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);
				
				//Enregistrer notre user quelque part pour pouvoir le récup potentiellement plus tard
				UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				//On donne à Spring le contexte de sécurité dans lequel s'exécuter
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		} catch (Exception e) {
			System.out.println("Cannot set user authentication: " + e.getMessage());
		}
		
		filterChain.doFilter(request, response);
	}
	
	//Check si on a un token --> le retourne ou non
	private String getTokenFromHeader(HttpServletRequest request) {
		String authorization = request.getHeader("Authorization");
		
		if (authorization != null && authorization.startsWith("Bearer ")) {
			return authorization.substring(7);
		}
		
		return null;
	}
	

}
