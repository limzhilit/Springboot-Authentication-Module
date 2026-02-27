package ie.atu.Authentication.service;

import ie.atu.Authentication.config.JwtUtil;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.model.VerificationToken;
import ie.atu.Authentication.repository.UserRepository;
import ie.atu.Authentication.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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

    // Verify password first to prevent activation email spam for random email
    // lookups
    if (!passwordEncoder.matches(password, user.getPassword())) {
      throw new org.springframework.security.authentication.BadCredentialsException("Incorrect password");
    }

    if (!user.isVerified()) {
      // Send email now? No, the user wants it in global exception.
      // So we throw DisabledException and carry the email in the message string.
      throw new org.springframework.security.authentication.DisabledException(email);
    }

    // Now we know password is correct and user is verified, so we authenticate
    Authentication auth = authManager.authenticate(
        new UsernamePasswordAuthenticationToken(email, password));

    user = (User) auth.getPrincipal();
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
    userRepo.findByEmail(email).ifPresent(user -> {
      emailService.sendPasswordResetEmail(user);
    });
  }

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
}
