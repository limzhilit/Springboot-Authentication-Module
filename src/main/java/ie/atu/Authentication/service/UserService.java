package ie.atu.Authentication.service;

import ie.atu.Authentication.security.JwtUtil;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.repository.UserRepository;
import io.jsonwebtoken.Claims;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

  private final AuthService authService;
  private final UserRepository userRepo;
  private final AuthenticationManager authManager;
  private final JwtUtil jwtUtil;
  private final EmailService emailService;
  private final PasswordEncoder passwordEncoder;

  public Map<String, String> upsertUser(String email, String password) {
    System.out.println("upsertUser called with email: " + email);
    User user = userRepo.findByEmail(email).orElse(null);
    System.out.println("User found: " + user);

    if (user == null) {
      createNewUser(email, password);
      return null;
    }

    if (!user.isVerified()) {
      emailService.sendActivationEmail(user);
      System.out.println("Email sent: " + user);
      System.out.println("user not verified" );

      return null;
    }

    System.out.println("user authenticating" );

    Authentication auth = authManager.authenticate(
        new UsernamePasswordAuthenticationToken(email, password)
    );

    System.out.println("user authenticated" );

    return authService.login(user);
  }

  public void createNewUser(String email, String rawPassword) {
    User user = new User();
    user.setEmail(email);
    user.setPassword(passwordEncoder.encode(rawPassword));
    user.setVerified(false);
    userRepo.save(user);
    emailService.sendActivationEmail(user);
    System.out.println("User created: " + user);
  }

  public void initiatePasswordReset(String email) {
    userRepo.findByEmail(email).ifPresent(emailService::sendPasswordResetEmail);
  }

  @Transactional
  public ResponseEntity<?> resetPassword(String token, String newPassword) {
    long userId;
    try {
      Claims claims = jwtUtil.validateToken(token);
      userId = Long.parseLong(claims.getSubject());
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "Invalid or expired activation token."));
    }

    User user = userRepo.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found"));

    user.setPassword(passwordEncoder.encode(newPassword));
    userRepo.save(user);
    return ResponseEntity.ok(Map.of("message", "Password has been reset successfully."));
  }

  @Transactional
  public ResponseEntity<?> activateAccount(String token) {
    long userId;
    try {
      Claims claims = jwtUtil.validateToken(token);
      userId = Long.parseLong(claims.getSubject());
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "Invalid or expired activation token."));
    }

    User user = userRepo.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found"));

    user.setVerified(true);
    userRepo.save(user);

    Map<String, String> tokens = authService.login(user);
    String encodedAccessToken = URLEncoder.encode(tokens.get("accessToken"), StandardCharsets.UTF_8);
    String encodedRefreshToken = URLEncoder.encode(tokens.get("refreshToken"), StandardCharsets.UTF_8);

    return ResponseEntity.status(HttpStatus.FOUND)
        .header("Location",
            "http://localhost:5173/sign-in?token=" + encodedAccessToken + "&refreshToken=" + encodedRefreshToken
                + "&activated=true")
        .build();
  }

}
