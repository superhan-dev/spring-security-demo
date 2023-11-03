package com.superhan.springsecuritydemo.common.security.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtils {

  // Key가 짧으면 에러를 내보낸다.
  private String SECRET_KEY = "1847ec9ca5c54823886d0300d2b4e5e41847ec9ca5c54823886d0300d2b4e5e41847ec9ca5c54823886d0300d2b4e5e4";

  // private Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    return Jwts
        .parserBuilder()
        .setSigningKey(SECRET_KEY)
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  private Boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  public String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    return createToken(claims, userDetails.getUsername());
  }

  private String createToken(Map<String, Object> claims, String subject) {

    // java.security.Security.addProvider(
    // new org.bouncycastle.jce.provider.BouncyCastleProvider());
    // PemReader pemReader = new PemReader(new StringReader(SECRET_KEY));

    // PemObject pemObject;
    // pemObject = pemReader.readPemObject();

    // KeyFactory factory = KeyFactory.getInstance("RSA");
    // byte[] content = pemObject.getContent();
    // PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
    // RSAPrivateKey privateKey = (RSAPrivateKey)
    // factory.generatePrivate(privKeySpec);

    return Jwts.builder().setClaims(claims)
        .setSubject(subject)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
        .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
  }

  public Boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }
}