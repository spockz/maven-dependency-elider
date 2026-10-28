/* WHY: Exposes a small HTTP behavior that remains observable when the application is packaged
 * with graph-backed dependency decisions and intra-JAR trimming.
 */

package io.github.spockz.example.springboot;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Keeps the greeting endpoint separate from startup.
 *
 * <p>The controller is the HTTP boundary.
 *
 * <p>This lets the fixture exercise packaged web behavior directly.
 */
@RestController
@SuppressWarnings("PMD.AtLeastOneConstructor")
public class HelloController {

  /** Returns {@code {"message":"hello"}} from the {@code /api/hello} HTTP endpoint. */
  @GetMapping("/api/hello")
  public Map<String, String> hello() {
    return Map.of("message", "hello");
  }
}
