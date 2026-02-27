package ie.atu.Authentication.controller;

import ie.atu.Authentication.dto.LoginRequest;
import ie.atu.Authentication.model.VerificationToken;
import ie.atu.Authentication.repository.VerificationTokenRepository;
import ie.atu.Authentication.service.UserService;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
  private final UserRepository userRepo;
  private final UserService userService;
  private final VerificationTokenRepository tokenRepo;

  @PostMapping("/sign-in")
  // If validation fails:
  // Controller method never runs.
  // Spring automatically returns 400 Bad Request
  public ResponseEntity<?> signIn(@Valid @RequestBody LoginRequest req) {
    String token = userService.loginOrCreatePendingUser(req.getEmail(), req.getPassword(), req.isRememberMe());

    if (token == null) {
      return ResponseEntity.ok(Map.of(
          "message", "Check your email to activate your account."));
    }

    User user = userRepo.findByEmail(req.getEmail()).orElseThrow();

    return ResponseEntity.ok(Map.of(
        "token", token,
        "hasCandidateProfile", user.isHasCandidateProfile(),
        "hasEmployerProfile", user.isHasEmployerProfile(),
        "lastActiveRole", user.getLastActiveRole() != null ? user.getLastActiveRole() : ""));
  }

  @GetMapping("/activate")
  public ResponseEntity<?> activateAccount(@RequestParam String token) {
    VerificationToken verificationToken = tokenRepo.findByToken(token)
        .orElseThrow(() -> new RuntimeException("Invalid token"));

    if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "Token expired"));
    }

    User user = verificationToken.getUser();
    user.setVerified(true);
    userRepo.save(user);

    // Redirect to frontend sign-in page with success flag
    return ResponseEntity.status(HttpStatus.FOUND)
        .header("Location", "http://localhost:5173/sign-in?activated=true")
        .build();
  }

  @PostMapping("/forgot-password")
  public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> body) {
    userService.initiatePasswordReset(body.get("email"));
    return ResponseEntity.ok(Map.of("message", "If an account exists with that email, a reset link has been sent."));
  }

  @PostMapping("/reset-password")
  public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
    boolean success = userService.resetPassword(body.get("token"), body.get("newPassword"));
    if (!success) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(Map.of("error", "Invalid or expired token"));
    }
    return ResponseEntity.ok(Map.of("message", "Password reset successfully! You can now log in."));
  }
}