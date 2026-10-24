/* WHY: Starts the Spring Boot reference application so dependency-elision checks can exercise
 * a real web endpoint.
 */

package io.github.spockz.example.springboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Entry point for the Spring Boot reference application. */
@SpringBootApplication
public class ExampleApplication {

  /** Starts the embedded web server and Spring application context. */
  public static void main(final String[] args) {
    SpringApplication.run(ExampleApplication.class, args);
  }
}
