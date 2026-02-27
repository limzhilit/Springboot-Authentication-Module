package ie.atu.Authentication.config;

import ie.atu.Authentication.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

  @Value("${jwt.secret}")
  private String secret;

  private Key getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secret);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public String generateToken(User user, boolean rememberMe) {
    long currentExpiration = rememberMe ? 7 * 24 * 60 * 60 * 1000L : 60 * 60 * 1000L; // 7 days or 1 hour

    return Jwts.builder()
        .setSubject(user.getEmail())
        .claim("role", "USER")
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + currentExpiration))
        .signWith(getSigningKey())
        .compact();
  }

  public Claims validateToken(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(getSigningKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
  }
}
