package ie.atu.Authentication.repository;

import ie.atu.Authentication.model.RefreshToken;
import ie.atu.Authentication.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Date;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
  Optional<RefreshToken> findByToken(String token);
  void deleteAllByUser(User user);         // used on logout
  void deleteAllByExpiresAtBefore(Date now); // cleanup job
}