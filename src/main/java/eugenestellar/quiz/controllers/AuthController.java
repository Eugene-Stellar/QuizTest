package eugenestellar.quiz.controllers;

import eugenestellar.quiz.exception.NotFoundRefreshTokenException;
import eugenestellar.quiz.model.AuthUserDto;
import eugenestellar.quiz.model.ResponseTokenAndInfoDto;
import eugenestellar.quiz.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("/register")
  public ResponseEntity<ResponseTokenAndInfoDto> register(@Valid @RequestBody AuthUserDto userDto) { // @Valid does log WARN

    ResponseTokenAndInfoDto responseTokenAndInfoDto = authService.register(userDto);

    ResponseCookie cookie = authService.setRefreshTokenInCookie(responseTokenAndInfoDto.getUsername());

    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookie.toString())
        .body(responseTokenAndInfoDto);
  }

  @PostMapping("/login")
  public ResponseEntity<ResponseTokenAndInfoDto> login(@Valid @RequestBody AuthUserDto userDto) {

    ResponseTokenAndInfoDto responseTokenAndInfoDto = authService.login(userDto);

    ResponseCookie cookie = authService.setRefreshTokenInCookie(responseTokenAndInfoDto.getUsername());

    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookie.toString())
        .body(responseTokenAndInfoDto);
  }

  @PostMapping("/refresh")
  public ResponseEntity<ResponseTokenAndInfoDto> refresh(@CookieValue(name = "refresh-token", required = false) String refreshToken) {

    if (refreshToken == null || refreshToken.isBlank())
      throw new NotFoundRefreshTokenException("Refresh token wasn't provided");

    ResponseTokenAndInfoDto responseTokenAndInfoDto = authService.getNewAccessToken(refreshToken);

    return ResponseEntity.ok().body(responseTokenAndInfoDto);
  }
//    @PostMapping("/logout")
//  public ResponseEntity<Map<String, String>> logout() {
//
//    SecurityContextHolder.clearContext(); // just in case
//
//    ResponseCookie deleteCookie = ResponseCookie.from("refresh-token")
//        .httpOnly(true)
//        .secure(true)
//        .sameSite("None")
//        .path("/")
//        .maxAge(0)
//        .build();
//
//    return ResponseEntity.ok()
//        .header(HttpHeaders.SET_COOKIE, deleteCookie.toString())
//        .body(Map.of("message","Logged out successfully"));
//  }
}