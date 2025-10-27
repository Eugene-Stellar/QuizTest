package eugenestellar.quiz.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@ControllerAdvice
public class GlobalExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
    List<FieldError> fieldErrors = ex.getFieldErrors();
    return ResponseEntity.badRequest().body(Map // Map can't contain null
        .of("error", Objects.requireNonNull(fieldErrors.get(0).getDefaultMessage())));
  }

  @ExceptionHandler(UsernameAlreadyExistException.class)
  public ResponseEntity<Map<String, String>> handleUsernameAlreadyExist(UsernameAlreadyExistException ex) {
    return ResponseEntity
        .status(HttpStatus.CONFLICT)
        .body(Map.of("error", ex.getMessage()));
  }
  @ExceptionHandler(NotFoundUserOrIncorrectPasswordException.class)
  public ResponseEntity<Map<String, String>> handleNotFoundUser(NotFoundUserOrIncorrectPasswordException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
              .body(Map.of("error", ex.getMessage()));
  }

  @ExceptionHandler(ExpiredRefreshTokenException.class)
  public ResponseEntity<Map<String, String>> handleExpiredRefreshToken(ExpiredRefreshTokenException ex) {
    SecurityContextHolder.clearContext(); // just in case

    ResponseCookie deleteCookie = ResponseCookie.from("refresh-token")
        .httpOnly(true)
        .secure(true)
        .sameSite("None")
        .path("/")
        .maxAge(0)
        .build();

    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .header(HttpHeaders.SET_COOKIE, deleteCookie.toString())
        .body(Map.of("error", ex.getMessage()));
  }

  @ExceptionHandler(NotFoundRefreshTokenException.class)
  public ResponseEntity<Map<String, String>> handleNotFoundRefreshToken(NotFoundRefreshTokenException ex) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .body(Map.of("error", ex.getMessage()));
  }

  @ExceptionHandler(UserNotFoundForTokenException.class)
  public ResponseEntity<Map<String, String>> handleUserNotFoundForToken(UserNotFoundForTokenException ex) {
    log.warn("Refresh token validation failed: {}", ex.getMessage());

    SecurityContextHolder.clearContext(); // just in case
    ResponseCookie deleteCookie = ResponseCookie.from("refresh-token")
        .httpOnly(true)
        .secure(true)
        .sameSite("None")
        .path("/")
        .maxAge(0)
        .build();

    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .header(HttpHeaders.SET_COOKIE, deleteCookie.toString())
        .body(Map.of("error", "User for this token no longer exists"));

  }
}