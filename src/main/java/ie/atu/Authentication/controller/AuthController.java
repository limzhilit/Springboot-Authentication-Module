package ie.atu.Authentication.controller;

import ie.atu.Authentication.security.JwtUtil;
import ie.atu.Authentication.dto.LoginRequest;
import ie.atu.Authentication.service.AuthService;
import ie.atu.Authentication.service.UserService;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final UserService userService;
  private final UserRepository userRepo;
  private final JwtUtil jwtUtil;

  @PostMapping("/sign-in")
  public ResponseEntity<?> signIn(@Valid @RequestBody LoginRequest req) {
    Map<String, String> tokens = userService.upsertUser(req.getEmail(), req.getPassword());

    User user = userRepo.findByEmail(req.getEmail()).orElseThrow();

    // ✅ Set refresh token as HttpOnly cookie
    ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", tokens.get("refreshToken"))
        .httpOnly(true)      // JS cannot access it
        .secure(false)        // HTTPS only
        .path("/") // only sent to this endpoint
        .maxAge(30 * 24 * 60 * 60) // 30 days
        .sameSite("Lax")
        .build();

    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
        .body(Map.of(
            "token", tokens.get("accessToken"), // ✅ access token still in body
            "hasCandidateProfile", user.isHasCandidateProfile(),
            "hasEmployerProfile", user.isHasEmployerProfile(),
            "lastActiveRole", user.getLastActiveRole() != null ? user.getLastActiveRole() : ""
        ));
  }

  @PostMapping("/refresh")
  public ResponseEntity<?> refresh(
      @CookieValue(name = "refreshToken", required = false) String refreshToken) {
    if (refreshToken == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token missing");
    }
    Map<String, String> tokens = authService.refresh(refreshToken);

    ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", tokens.get("refreshToken"))
        .httpOnly(true)
        .secure(false)
        .path("/")
        .maxAge(30 * 24 * 60 * 60)
        .sameSite("Lax")
        .build();

    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
        .body(Map.of("accessToken", tokens.get("accessToken")));
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
      String token = authHeader.substring(7);
      String idStr = jwtUtil.validateToken(token).getSubject();
      if (idStr != null) {
        try {
          Long id = Long.parseLong(idStr);
          userRepo.findById(id).ifPresent(authService::logout);
        } catch (NumberFormatException ignored) {
        }
      }
    }
    return ResponseEntity.noContent().build();
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
    return userService.resetPassword(body.get("token"), body.get("newPassword"));
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
      String idStr = jwtUtil.validateToken(token).getSubject();

      if (idStr == null) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", "Invalid or expired token"));
      }

      Long id;
      try {
        id = Long.parseLong(idStr);
      } catch (NumberFormatException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", "Invalid token subject format"));
      }

      // 3. Fetch User and Map Response
      return userRepo.findById(id)
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