package com.dy.security;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtHelper {
	public static final long JWT_TOKEN_VALIDIY = 5 * 60 * 60;
	private String secret = "YvBuK7eCOH1SmfwsChuHE7Fwd+BbCf2Lg90LRlPTizi/3gf22eed6WMxWCacZ7B6\n";

	// retrive username from jwt token
	public String getUsername(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	// expire date
	public Date getExpireationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	// check token has expire
	private boolean isTokenExpired(String token) {
		final Date date = getExpireationDateFromToken(token);
		return date.before(new Date());
	}

	// generate token for user
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();

		return doGenerateToken(claims, userDetails.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claims, String subject) {

		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDIY * 1000))
				.signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
	}

	private Key getSignKey() {
		byte[] keyBytes = Decoders.BASE64.decode(secret);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	// validate token

	public Boolean vaildateToken(String token, UserDetails userDetails) {
		final String username = getUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsReslover) {

		final Claims claims = getAllClaimsFromToken(token);

		return claimsReslover.apply(claims);

	}

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parserBuilder().setSigningKey(secret.getBytes()).build().parseClaimsJws(token).getBody();
	}

}
