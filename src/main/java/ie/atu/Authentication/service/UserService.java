package ie.atu.Authentication.service;

import ie.atu.Authentication.config.JwtUtil;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.repository.UserRepository;
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

  public String loginOrCreatePendingUser(String email, String password) {
    User user = userRepo.findByEmail(email).orElse(null);

    if (user == null) {
      return createPendingUser(email, password);
    }

    // Calling Spring Security’s authentication engine
    // - Load user from DB
    // - Compare password using BCryptPasswordEncoder
    // - Call isEnabled() (checks verified)
    // - Throw exception if invalid
    // - Return authenticated object if valid
    Authentication auth = authManager.authenticate(
        new UsernamePasswordAuthenticationToken(email, password)
    );

    user = (User) auth.getPrincipal();
    return jwtUtil.generateToken(user);
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
}
