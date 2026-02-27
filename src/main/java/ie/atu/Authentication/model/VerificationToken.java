package ie.atu.Authentication.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
public class VerificationToken {
  @Id @GeneratedValue
  private Long id;

  private String token;

  @Enumerated(EnumType.STRING)
  private TokenType type;

  private LocalDateTime expiryDate;

  @ManyToOne
  private User user;

  public enum TokenType { SIGNUP, PASSWORD_RESET }
}
