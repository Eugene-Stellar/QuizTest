package eugenestellar.quiz.exception;

public class NotFoundRefreshTokenException extends RuntimeException {
  public NotFoundRefreshTokenException(String message) {
    super(message);
  }
}
