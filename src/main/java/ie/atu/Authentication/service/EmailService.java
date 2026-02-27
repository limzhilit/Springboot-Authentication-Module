package ie.atu.Authentication.service;

import ie.atu.Authentication.model.User;
import ie.atu.Authentication.model.VerificationToken;
import ie.atu.Authentication.repository.VerificationTokenRepository;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class EmailService {

  private final JavaMailSender mailSender;
  private final VerificationTokenRepository tokenRepo;

  public EmailService(JavaMailSender mailSender, VerificationTokenRepository tokenRepo) {
    this.mailSender = mailSender;
    this.tokenRepo = tokenRepo;
  }

  public void sendActivationEmail(User user) {
    String token = createToken(user, VerificationToken.TokenType.SIGNUP);
    String link = "http://localhost:8080/api/auth/activate?token=" + token;

    sendEmail(user.getEmail(), "Activate Your Account", "Click the link to activate your account: " + link);
  }

  public void sendPasswordResetEmail(User user) {
    String token = createToken(user, VerificationToken.TokenType.PASSWORD_RESET);
    // The reset page will live on the frontend (Port 5173)
    String link = "http://localhost:5173/reset-password?token=" + token;

    sendEmail(user.getEmail(), "Reset Your Password", "Click the link to reset your password: " + link);
  }

  private String createToken(User user, VerificationToken.TokenType type) {
    String token = UUID.randomUUID().toString();
    VerificationToken vt = new VerificationToken();
    vt.setToken(token);
    vt.setUser(user);
    vt.setType(type);
    vt.setExpiryDate(LocalDateTime.now().plusHours(24));
    tokenRepo.save(vt);
    return token;
  }

  private void sendEmail(String to, String subject, String text) {
    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(to);
    message.setSubject(subject);
    message.setText(text);

    try {
      mailSender.send(message);
    } catch (Exception e) {
      System.err.println("Failed to send email to " + to + ": " + e.getMessage());
    }
  }
}