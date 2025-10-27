package eugenestellar.quiz.exception;

public class ExpiredRefreshTokenException extends RuntimeException {
  public ExpiredRefreshTokenException(String message) {
    super(message);
  }
}
