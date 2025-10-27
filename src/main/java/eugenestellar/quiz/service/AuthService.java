package eugenestellar.quiz.service;

import com.auth0.jwt.exceptions.JWTVerificationException;
import eugenestellar.quiz.exception.ExpiredRefreshTokenException;
import eugenestellar.quiz.exception.NotFoundUserOrIncorrectPasswordException;
import eugenestellar.quiz.exception.UserNotFoundForTokenException;
import eugenestellar.quiz.exception.UsernameAlreadyExistException;
import eugenestellar.quiz.model.AuthUserDto;
import eugenestellar.quiz.model.ResponseTokenAndInfoDto;
import eugenestellar.quiz.model.User;
import eugenestellar.quiz.repository.UserRepo;
import eugenestellar.quiz.util.JwtUtil;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;


@Service
public class AuthService {

  private final UserRepo userRepo;
  private final PasswordEncoder passwordEncoder;
  private final JwtUtil jwtUtil;

  public AuthService(JwtUtil jwtUtil, UserRepo userRepo, PasswordEncoder passwordEncoder) {
    this.jwtUtil = jwtUtil;
    this.userRepo = userRepo;
    this.passwordEncoder = passwordEncoder;
  }

  public ResponseTokenAndInfoDto register(AuthUserDto userDto) {

    String username = userDto.getUsername();

    if (userRepo.findByUsername(username).isPresent())
      throw new UsernameAlreadyExistException("This username has been already taken");

    // create user in order to save it in DB
    User userForDb = new User();
    userForDb.setPassword(passwordEncoder.encode(userDto.getPassword()));
    userForDb.setUsername(username);
    User savedUsed = userRepo.save(userForDb);

    String token = jwtUtil.generateToken(username, true);

    return new ResponseTokenAndInfoDto(token, savedUsed.getId(), username);
  }

  public ResponseCookie setRefreshTokenInCookie(String username) {

    return ResponseCookie.from("refresh-token", jwtUtil.generateToken(username, false))
        .httpOnly(true)
        .secure(true)
        .sameSite("None") // for cross-domain access
        .path("/") // cookie scope i.e. which paths will be the cookie send to, /auth by default(matched with Controller path)
        .maxAge(Duration.ofDays(30))
        .build();
  }

  public ResponseTokenAndInfoDto login(AuthUserDto userDto) {

    String username = userDto.getUsername();

    var userFromDbOptional = userRepo.findByUsername(username);


    if (userFromDbOptional.isEmpty())
      throw new NotFoundUserOrIncorrectPasswordException("There's no user with a name " + username);

    User userFromDb = userFromDbOptional.get();

    if (!passwordEncoder.matches(userDto.getPassword(), userFromDb.getPassword()))
      throw new NotFoundUserOrIncorrectPasswordException("The password is incorrect");

    String token = jwtUtil.generateToken(username, true);

    return new ResponseTokenAndInfoDto(token, userFromDb.getId(), username);

  }

  public ResponseTokenAndInfoDto getNewAccessToken(String refreshToken) {
    try {
      String username = jwtUtil.validateRefreshTokenAndRetrieveClaim(refreshToken);
      String accessToken = jwtUtil.generateToken(username, true);

      User user = userRepo.findByUsername(username)
          .orElseThrow(() -> new UserNotFoundForTokenException("User not found with username: " + username));

      return new ResponseTokenAndInfoDto(accessToken, user.getId(), username);

    } catch (JWTVerificationException ex) {
      throw new ExpiredRefreshTokenException("Invalid or expired refresh token");
    }
  }
}
