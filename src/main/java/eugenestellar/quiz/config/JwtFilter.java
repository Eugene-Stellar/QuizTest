package eugenestellar.quiz.config;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eugenestellar.quiz.util.JwtUtil;
import eugenestellar.quiz.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);

  private final JwtUtil jwtUtil;
  private final CustomUserDetailsService userDetailsService;
  private final ObjectMapper objectMapper;

  public JwtFilter(JwtUtil jwtUtil, CustomUserDetailsService userDetailsService, ObjectMapper objectMapper) {
    this.jwtUtil = jwtUtil;
    this.userDetailsService = userDetailsService;
    this.objectMapper = objectMapper;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

    String authHeader = request.getHeader("Authorization");

    if (authHeader != null && authHeader.startsWith("Bearer ") && SecurityContextHolder.getContext().getAuthentication() == null) {
      try {
        String token = authHeader.substring(7);
        String username = jwtUtil.validateAccessTokenAndRetrieveClaim(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        UsernamePasswordAuthenticationToken authToken =
            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);
      } catch (JWTVerificationException ex) {

        SecurityContextHolder.clearContext();
        log.warn("Invalid JWT token. {}", ex.getMessage());
        sendCustomError(response, "Invalid JWT Token");
        return;

      } catch (UsernameNotFoundException ex) {

        log.warn("Unknown user. {}", ex.getMessage());
        SecurityContextHolder.clearContext();
        sendCustomError(response, "Unknown user");
        return;
      }
    }
    filterChain.doFilter(request, response);
  }

  private void sendCustomError(HttpServletResponse response, String message) throws IOException {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

    response.getWriter().write(objectMapper.writeValueAsString(Map.of("error", message)));
  }
}