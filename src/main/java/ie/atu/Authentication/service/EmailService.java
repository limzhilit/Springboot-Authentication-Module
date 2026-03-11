package ie.atu.Authentication.service;

import ie.atu.Authentication.config.AppConfig;
import ie.atu.Authentication.model.User;
import ie.atu.Authentication.security.JwtUtil;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class EmailService {

  private final JavaMailSender mailSender;
  private final AppConfig appConfig;
  private final JwtUtil jwtUtil;

  public void sendActivationEmail(User user) {
    String token = jwtUtil.generateAccessToken(user);
    String link = appConfig.getGatewayUrl() + "/api/auth/activate?token=" + token;

    String html = """
        <html>
          <body>
            <br>
            <a href="%s" style="margin: 10px 20px; padding: 10px 20px; background-color: #000000; color: white; text-decoration: none; border-radius: 0px;">
              Activate Account
            </a>
          </body>
        </html>
        """
        .formatted(link);

    sendHtmlEmail(user.getEmail(), "Opportune Account Activation", html);
  }

  public void sendPasswordResetEmail(User user) {
    String token = jwtUtil.generateAccessToken(user);
    // The reset page will live on the frontend (Port 5173)
    String link = appConfig.getFrontendUrl() + "/reset-password?token=" + token;

    String html = """
        <html>
          <body>
          <br>
            <a href="%s" style="margin: 10px 20px; padding: 10px 20px; background-color: #000000; color: white; text-decoration: none; border-radius: 0px;">
              Reset Password
            </a>
          </body>
        </html>
        """
        .formatted(link);

    sendHtmlEmail(user.getEmail(), "Opportune Password Reset", html);

  }

  private void sendHtmlEmail(String to, String subject, String html) {
    try {
      MimeMessage message = mailSender.createMimeMessage();
      MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

      helper.setTo(to);
      helper.setSubject(subject);
      helper.setText(html, true); // true = HTML content

      mailSender.send(message);
    } catch (Exception e) {
      System.err.println("Failed to send email to " + to + ": " + e.getMessage());
    }
  }
}