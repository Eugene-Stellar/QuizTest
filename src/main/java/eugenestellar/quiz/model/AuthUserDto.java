package eugenestellar.quiz.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class AuthUserDto {

  @NotBlank(message = "Name can't be empty")
  @Size(max = 20, min = 3, message = "Username length must be between 3 and 20 characters") // code level
  @Pattern(regexp = "^[\\p{L}\\p{N}_]+$", message = "Username can contain only letters, numbers and underscore")
  private String username;

  @NotBlank(message = "Password can't be empty")
  @Size(max = 32, min = 6, message = "Password length must be between 6 and 32 characters")
  private String password;
}