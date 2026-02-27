package ie.atu.Authentication.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class AuthExceptionHandler {

  @ExceptionHandler(DisabledException.class)
  public ResponseEntity<?> handleDisabled(DisabledException ex) {
    return ResponseEntity
        .status(HttpStatus.FORBIDDEN)
        .body(Map.of("error", "Account not activated. Please check your email."));
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<?> handleBadCredentials(BadCredentialsException ex) {
    return ResponseEntity
        .status(HttpStatus.UNAUTHORIZED)
        .body(Map.of("error", "Incorrect password"));
  }

  @ExceptionHandler(UsernameNotFoundException.class)
  public ResponseEntity<?> handleUserNotFound(UsernameNotFoundException ex) {
    return ResponseEntity
        .status(HttpStatus.NOT_FOUND)
        .body(Map.of("error", "Account not found. Please register."));
  }
}
