package eugenestellar.quiz.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;

@Component
public class JwtUtil {

  @Value("${SECRET_WORD}")
  private String secret;

  public String generateToken(String username, boolean accessToken) {
    Date expirationDate = accessToken ? Date.from(ZonedDateTime.now().plusMinutes(15).toInstant())
    : Date.from(ZonedDateTime.now().plusDays(30).toInstant());

    return JWT.create()
        .withSubject("User details")
        .withClaim("username", username)
        .withClaim("type", accessToken ? "access" : "refresh")
        .withIssuedAt(new Date())
        .withIssuer("auth-service")
        .withExpiresAt(expirationDate)
        .sign(Algorithm.HMAC256(secret));
  }

  public String validateAccessTokenAndRetrieveClaim(String token) throws JWTVerificationException {
    JWTVerifier verifier = JWT
        .require(Algorithm.HMAC256(secret))
        .withSubject("User details")
        .withIssuer("auth-service")
        .withClaim("type", "access")
        .build();

    DecodedJWT jwt = verifier.verify(token);

    return jwt.getClaim("username").asString();
  }

  public String validateRefreshTokenAndRetrieveClaim(String token) throws JWTVerificationException {
    JWTVerifier verifier = JWT
        .require(Algorithm.HMAC256(secret))
        .withSubject("User details")
        .withIssuer("auth-service")
        .withClaim("type", "refresh")
        .build();

    DecodedJWT jwt = verifier.verify(token);

    return jwt.getClaim("username").asString();
  }
}