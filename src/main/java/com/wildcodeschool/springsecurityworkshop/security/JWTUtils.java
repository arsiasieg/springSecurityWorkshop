package com.wildcodeschool.springsecurityworkshop.security;

import java.security.SignatureException;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JWTUtils {
	
	@Value("${wcslyon.app.jwtExpirationMs}")
	private int expirationMs;
	
	@Value("${wcslyon.app.jwtSecret}")
	private String jwtSecret;

	public String generateToken(UserDetailsImpl userDetailsImpl) {
		return Jwts.builder()
			.setSubject(userDetailsImpl.getUsername())  					//le token doit être construit avec mon user
			.setIssuedAt(new Date()) 										// date de création du token
			.setExpiration(new Date((new Date()).getTime() + expirationMs))	//on va cherche la date actuelle (en ms) + le temps d'expiration -> date où le token va expirer
			.signWith(SignatureAlgorithm.HS512, jwtSecret)					//création de la signature via la jwtSecret du app.properties et l'encodeur (algorithm HS512)
			.compact();
	}
	
	//Décodage du token
	public String getUsernameFromToken(String token) {
		//On va décoder le token grâce au "parser" via la clé secret. Bien on va chercher les claims (les properties du token en gros), puis le body et le subject qui contient le username
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}
	
	public boolean isValidToken(String token) throws SignatureException {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException e) {
        	System.out.println("Invalid JWT token: " + e.getMessage());
        } catch (ExpiredJwtException e) {
        	System.out.println("JWT token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
        	System.out.println("JWT token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
        	System.out.println("JWT claims string is empty: " + e.getMessage());
        }

        return false;

    }
}
