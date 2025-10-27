package eugenestellar.quiz.exception;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class UserNotFoundForTokenException extends UsernameNotFoundException {
  public UserNotFoundForTokenException(String message) {
    super(message);
  }
}