package ie.atu.Authentication.service;

import ie.atu.Authentication.security.JwtUtil;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.model.VerificationToken;
import ie.atu.Authentication.repository.UserRepository;
import ie.atu.Authentication.repository.VerificationTokenRepository;
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

  private final UserRepository userRepo;
  private final AuthenticationManager authManager;
  private final JwtUtil jwtUtil;
  private final EmailService emailService;
  private final PasswordEncoder passwordEncoder;
  private final VerificationTokenRepository tokenRepo;

  public String loginOrCreatePendingUser(String email, String password, boolean rememberMe) {
    User user = userRepo.findByEmail(email).orElse(null);

    if (user == null) {
      return createPendingUser(email, password);
    }
    if (!user.isVerified()) {
      userRepo.findByEmail(email).ifPresent(emailService::sendActivationEmail);
      return null;
    }

    Authentication auth = authManager.authenticate(
        new UsernamePasswordAuthenticationToken(email, password)
    );

    user = userRepo.findByEmail(email)
        .orElseThrow(() -> new RuntimeException("User not found"));

    return jwtUtil.generateToken(user, rememberMe);
  }

  public String createPendingUser(String email, String rawPassword) {
    User user = new User();
    user.setEmail(email);
    user.setPassword(passwordEncoder.encode(rawPassword));
    user.setVerified(false);
    userRepo.save(user);

    emailService.sendActivationEmail(user);

    return null;
  }

  public void initiatePasswordReset(String email) {
    userRepo.findByEmail(email).ifPresent(emailService::sendPasswordResetEmail);
  }

  @Transactional
  public boolean resetPassword(String token, String newPassword) {
    return tokenRepo.findByToken(token)
        .filter(vt -> vt.getType() == VerificationToken.TokenType.PASSWORD_RESET)
        .filter(vt -> vt.getExpiryDate().isAfter(java.time.LocalDateTime.now()))
        .map(vt -> {
          User user = vt.getUser();
          user.setPassword(passwordEncoder.encode(newPassword));
          user.setVerified(true); // reset implies valid email
          userRepo.save(user);
          tokenRepo.delete(vt);
          return true;
        }).orElse(false);
  }

  @Transactional
  public ResponseEntity<?> activateAccount(String token) {
    Optional<VerificationToken> optionalToken = tokenRepo.findByToken(token);

    if (optionalToken.isEmpty()) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "Activation token is invalid or not found."));
    }

    VerificationToken verificationToken = optionalToken.get();

    if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "Token expired"));
    }

    User user = verificationToken.getUser();
    if (user == null) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "User not found."));
    }

    user.setVerified(true);
    userRepo.save(user);

    tokenRepo.delete(verificationToken);

    String jwt = jwtUtil.generateToken(user, false);
    String encodedJwt = URLEncoder.encode(jwt, StandardCharsets.UTF_8);

    return ResponseEntity.status(HttpStatus.FOUND)
        .header("Location", "http://localhost:5173/sign-in?token=" + encodedJwt + "&activated=true")
        .build();
  }

}
