package ie.atu.Authentication.service;

import ie.atu.Authentication.security.JwtUtil;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.model.VerificationToken;
import ie.atu.Authentication.repository.UserRepository;
import ie.atu.Authentication.repository.VerificationTokenRepository;
import jakarta.transaction.Transactional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

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

      if (email != null && email.contains("@")) {
        userRepo.findByEmail(email).ifPresent(emailService::sendActivationEmail);
      }
    }

    Authentication auth = authManager.authenticate(
        new UsernamePasswordAuthenticationToken(email, password));

    user = (User) auth.getPrincipal();
    assert user != null;
    return jwtUtil.generateToken(user, rememberMe);
  }

  public String createPendingUser(String email, String rawPassword) {
    User user = new User();
    user.setEmail(email);
    user.setPassword(passwordEncoder.encode(rawPassword));
    user.setVerified(false);
    userRepo.save(user);

    emailService.sendActivationEmail(user);

    return null; // indicates "activation email sent"
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
    // 1. Find the token
    Optional<VerificationToken> optionalToken = tokenRepo.findByToken(token);

    if (optionalToken.isEmpty()) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "Activation token is invalid or not found."));
    }

    VerificationToken verificationToken = optionalToken.get();

    // 2. Check Expiration
    if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "Token expired"));
    }

    // 3. Get User and Verify
    User user = verificationToken.getUser();
    if (user == null) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "User not found."));
    }

    user.setVerified(true);
    userRepo.save(user);

    // 4. Cleanup: Delete the token so it can't be reused
    tokenRepo.delete(verificationToken);

    // 5. Generate JWT for auto-login
    String jwt = jwtUtil.generateToken(user, false);
    String encodedJwt = URLEncoder.encode(jwt, StandardCharsets.UTF_8);

    // 6. Redirect to Frontend
    return ResponseEntity.status(HttpStatus.FOUND)
        .header("Location", "http://localhost:5173/sign-in?token=" + encodedJwt + "&activated=true")
        .build();
  }

  @Override
  public @NonNull UserDetails loadUserByUsername(@NonNull String id) {
    Long userId = Long.parseLong(id);

    return userRepo.findById(userId)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }

}
