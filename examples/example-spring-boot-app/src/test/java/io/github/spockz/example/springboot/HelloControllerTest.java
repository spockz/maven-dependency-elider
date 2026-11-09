/* WHY: Checks HTTP and dependency behavior in the running app context. */

package io.github.spockz.example.springboot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URL;
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

  /** WHY: Codec trimming must match observed runtime use. */
  @Test
  void unusedCommonsCodecClassIsOnlyPresentInBaselineMode() {
    final boolean elisionMode = "elision".equals(System.getProperty("elide.mode"));
    final boolean codecClassMissing = resource("org/apache/commons/codec/binary/Hex.class") == null;
    org.junit.jupiter.api.Assertions.assertEquals(
        elisionMode,
        codecClassMissing,
        "Commons Codec Hex is absent only when the lifecycle elision mode is active");
  }

  /** Confirms mail remains available because the runtime trace observes mail classes. */
  @Test
  void mailClassesRemainAvailable() {
    assertThat(resource("jakarta/mail/Session.class") != null)
        .as("Jakarta Mail must remain on the classpath in baseline and elided builds")
        .isTrue();
  }

  private static URL resource(final String path) {
    return HelloControllerTest.class.getResource("/" + path);
  }
}
