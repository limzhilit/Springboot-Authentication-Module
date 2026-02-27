package ie.atu.Authentication.config;

import ie.atu.Authentication.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;import org.springframework.stereotype.Component;

import java.util.Date;


@Component
public class JwtUtil {

  @Value("${jwt.secret}")
  private String secret;

  private final long expiration = 24 * 60 * 60 * 1000; // 1 day

  public String generateToken(User user) {
    return Jwts.builder()
        .setSubject(user.getEmail())
        .claim("role", "USER")
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + expiration))
        .signWith(SignatureAlgorithm.HS256, secret)
        .compact();
  }

  public Claims validateToken(String token) {
    return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
  }
}
