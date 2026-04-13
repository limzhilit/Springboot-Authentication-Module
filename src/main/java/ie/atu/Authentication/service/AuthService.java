package ie.atu.Authentication.service;

import ie.atu.Authentication.model.RefreshToken;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.repository.RefreshTokenRepository;
//import ie.atu.Authentication.repository.UserRepository;
import ie.atu.Authentication.security.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final RefreshTokenRepository refreshTokenRepository;
  // private final UserRepository userRepository;
  private final JwtUtil jwtUtil;

  public Map<String, String> login(User user) {
    String accessToken = jwtUtil.generateAccessToken(user);
    String refreshToken = jwtUtil.generateRefreshToken(user);

    // Persist the refresh token
    RefreshToken entity = new RefreshToken();
    entity.setToken(refreshToken);
    entity.setUser(user);
    entity.setExpiresAt(new Date(System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000L));
    refreshTokenRepository.save(entity);

    return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
  }

  // Called when access token expires — client sends refresh token
  public Map<String, String> refresh(String refreshToken) {
    Claims claims = jwtUtil.validateToken(refreshToken);

    RefreshToken stored = refreshTokenRepository.findByToken(refreshToken)
        .orElseThrow(() -> {
          System.out.println("Refresh token not found in DB: " + refreshToken);
          return new RuntimeException("Token not found");
        });
    if (stored.isRevoked()) {
      System.out.println("Token revoked");
      throw new RuntimeException("Token revoked — please log in again");
    }
    System.out.println("Expires at: " + stored.getExpiresAt());

    User user = stored.getUser();

    // ✅ SLIDING WINDOW — reset the 30-day clock on every use
    String newRefreshToken = jwtUtil.generateRefreshToken(user);
    stored.setToken(newRefreshToken); // rotate token
    stored.setExpiresAt(new Date(System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000L));
    stored.setRevoked(false);
    refreshTokenRepository.save(stored);

    String newAccessToken = jwtUtil.generateAccessToken(user);

    return Map.of("accessToken", newAccessToken, "refreshToken", newRefreshToken);
  }

  // Google-style logout: revoke all sessions
  public void logout(User user) {
    refreshTokenRepository.deleteAllByUser(user);
  }
}