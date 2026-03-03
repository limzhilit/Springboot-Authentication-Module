package ie.atu.Authentication.controller;

import ie.atu.Authentication.security.JwtUtil;
import ie.atu.Authentication.dto.LoginRequest;
import ie.atu.Authentication.repository.VerificationTokenRepository;
import ie.atu.Authentication.service.UserService;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
  private final UserRepository userRepo;
  private final UserService userService;
  private final VerificationTokenRepository tokenRepo;
  private final JwtUtil jwtUtil;

  @PostMapping("/sign-in")
  // If validation fails:
  // Controller method never runs.
  // Spring automatically returns 400 Bad Request
  public ResponseEntity<?> signIn(@Valid @RequestBody LoginRequest req) {
    String token = userService.loginOrCreatePendingUser(req.getEmail(), req.getPassword(), req.isRememberMe());

    if (token == null) {
      return ResponseEntity.ok(Map.of(
          "message", "Account activation email sent."));
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
    return userService.activateAccount(token);
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

  @GetMapping("/me")
  public ResponseEntity<?> getCurrentUser(@RequestHeader(value = "Authorization", required = false) String authHeader) {
    try {
      // 1. Validate Header Structure
      if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", "Missing or invalid Authorization header"));
      }

      // 2. Extract and Validate Token
      String token = authHeader.substring(7);
      String email = jwtUtil.extractId(token);

      if (email == null) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", "Invalid or expired token"));
      }

      // 3. Fetch User and Map Response
      return userRepo.findByEmail(email)
          .map(user -> {
            Map<String, Object> response = new HashMap<>();
            response.put("email", user.getEmail());
            response.put("hasCandidateProfile", user.isHasCandidateProfile());
            response.put("hasEmployerProfile", user.isHasEmployerProfile());
            response.put("lastActiveRole", user.getLastActiveRole() != null ? user.getLastActiveRole() : "");
            return ResponseEntity.ok(response);
          })
          .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
              .body(Map.of("error", "User not found")));

    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(Map.of("error", "An unexpected error occurred"));
    }
  }
}