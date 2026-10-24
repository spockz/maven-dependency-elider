/* WHY: Confirms the HTTP contract with an observable response body while keeping the check
 * focused on the endpoint.
 */

package io.github.spockz.example.springboot;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;

/** Verifies the Spring Boot greeting endpoint over MockMvc. */
@WebMvcTest(HelloController.class)
class HelloControllerTest {

  /** MockMvc sends requests through Spring MVC without starting a server. */
  @Autowired private MockMvc mockMvc;

  /**
   * Creates a test for the greeting endpoint.
   *
   * <p>package-private constructor keeps the test class instantiable by JUnit.
   */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  HelloControllerTest() {}

  @Test
  @SuppressWarnings("PMD.UnitTestShouldIncludeAssert")
  void returnsJsonGreeting() throws Exception {
    mockMvc
        .perform(get("/api/hello"))
        .andExpect(status().isOk())
        .andExpect(content().json("{\"message\":\"hello\"}"));
  }
}
