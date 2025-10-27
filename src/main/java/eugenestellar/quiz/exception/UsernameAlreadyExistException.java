package eugenestellar.quiz.exception;

public class UsernameAlreadyExistException extends RuntimeException {
  public UsernameAlreadyExistException(String message) {
    super(message);
  }
}
