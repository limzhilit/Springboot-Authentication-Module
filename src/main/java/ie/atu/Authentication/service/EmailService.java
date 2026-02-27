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
    // 1️⃣ Generate token
    String token = UUID.randomUUID().toString();

    // 2️⃣ Save token to DB
    VerificationToken verificationToken = new VerificationToken();
    verificationToken.setToken(token);
    verificationToken.setUser(user);
    verificationToken.setExpiryDate(LocalDateTime.now().plusHours(24));
    tokenRepo.save(verificationToken);

    // 3️⃣ Build activation link
    String activationLink = "http://yourdomain.com/activate?token=" + token;

    // 4️⃣ Send email
    SimpleMailMessage message = new SimpleMailMessage();
    message.setTo(user.getEmail());
    message.setSubject("Activate Your Account");
    message.setText("Click the link to activate your account: " + activationLink);

    mailSender.send(message);
  }
}