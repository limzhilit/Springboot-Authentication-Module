package ie.atu.Authentication.security;

import ie.atu.Authentication.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
@Component
public class JwtUtil {

  @Value("${jwt.secret}")
  private String secret;

  // Access token: short-lived (15 mins)
  private static final long ACCESS_TOKEN_EXPIRY = 15 * 60 * 1000L;

  // Refresh token: long-lived (30 days, like Google)
  private static final long REFRESH_TOKEN_EXPIRY = 30L * 24 * 60 * 60 * 1000L;

  // Use SecretKey for better type safety in 0.12.x
  private javax.crypto.SecretKey getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secret);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public String generateAccessToken(User user) {
    return Jwts.builder()
        .subject(String.valueOf(user.getId()))
        .claim("role", "USER")
        .claim("type", "access")
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRY))
        .signWith(getSigningKey())
        .compact();
  }

  public String generateRefreshToken(User user) {
    return Jwts.builder()
        .subject(String.valueOf(user.getId()))
        .claim("type", "refresh")
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRY))
        .signWith(getSigningKey())
        .compact();
  }

  /*
  What it does (Step-by-Step)
    Starts the Parser: Jwts.parser() initializes the engine used to read JWT strings.
    Verifies Signature: .verifyWith(getSigningKey()) uses your private secret key to recalculate the digital signature. If even one character in the token was changed by a hacker, this step will throw an exception.
    Parses Claims: .parseSignedClaims(token) breaks the string into its original components (Header, Payload, Signature).
    Extracts Payload: .getPayload() returns the Claims object, which contains the user's data (email, roles, expiration date).
   */
  public Claims validateToken(String token) {
    return Jwts.parser()
        .verifyWith(getSigningKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }
}