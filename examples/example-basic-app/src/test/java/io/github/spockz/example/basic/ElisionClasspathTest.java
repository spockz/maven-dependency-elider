/* WHY: Makes the basic example's retained and elided dependencies observable in Surefire. */

package io.github.spockz.example.basic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.net.URL;
import org.junit.jupiter.api.Test;

/** Verifies the basic app keeps Jackson and conditionally removes Commons Codec. */
final class ElisionClasspathTest {

  /** Creates the focused runtime-classpath checks. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  ElisionClasspathTest() {}

  /** Confirms Jackson remains available for greeting serialization. */
  @Test
  void keepsJacksonAvailable() {
    assertNotNull(
        resource("com/fasterxml/jackson/databind/ObjectMapper.class"),
        "Jackson must remain because the application serializes its greeting");
  }

  /** Confirms the unused library follows the baseline or elided Maven classpath. */
  @Test
  void commonsCodecPresenceMatchesElisionMode() {
    final boolean expectedPresent = !Boolean.getBoolean("elider.verifyElision");
    assertEquals(
        expectedPresent,
        resource("org/apache/commons/codec/binary/Hex.class") != null,
        "Commons Codec should match baseline versus elided mode");
  }

  private static URL resource(final String path) {
    return ElisionClasspathTest.class.getResource("/" + path);
  }
}
