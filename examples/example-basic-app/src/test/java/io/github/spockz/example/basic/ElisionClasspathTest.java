/* WHY: Makes the basic example's retained and elided dependencies observable in Surefire. */

package io.github.spockz.example.basic;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.net.URL;
import org.junit.jupiter.api.Test;

/** Verifies the basic app retains the ZIP API it uses. */
final class ElisionClasspathTest {

  /** Creates the focused runtime-classpath checks. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  ElisionClasspathTest() {}

  /** Confirms the test classpath keeps the ZIP API required by the consumer source. */
  @Test
  void keepsTheReferencedZipArchiveApi() {
    assertNotNull(
        resource("org/apache/commons/compress/archivers/zip/ZipArchiveEntry.class"),
        "the referenced ZIP API must remain on the runtime classpath");
  }

  private static URL resource(final String path) {
    return ElisionClasspathTest.class.getResource("/" + path);
  }
}
