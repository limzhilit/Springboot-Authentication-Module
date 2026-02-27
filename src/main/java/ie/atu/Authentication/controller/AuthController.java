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

import javax.swing.*;
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
  //If validation fails:
  //Controller method never runs.
  //Spring automatically returns 400 Bad Request
  public ResponseEntity<?> signIn(@Valid @RequestBody LoginRequest req) {
    String token = userService.loginOrCreatePendingUser(req.getEmail(), req.getPassword());

    if (token == null) {
      return ResponseEntity.ok(Map.of(
          "message", "Check your email to activate your account."
      ));
    }

    return ResponseEntity.ok(Map.of("token", token));
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

    return ResponseEntity.ok(Map.of("message", "Account activated! You can now log in."));
  }
}