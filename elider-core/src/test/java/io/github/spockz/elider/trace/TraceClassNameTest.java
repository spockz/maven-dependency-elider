/* WHY: Verifies the JVM hidden-class name forms accepted by trace input filters. */

package io.github.spockz.elider.trace;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Verifies hidden class name handling across JDK trace formats. */
@SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
class TraceClassNameTest {
  /** Creates the package-visible test instance required by the project's test style. */
  TraceClassNameTest() {}

  @Test
  void recognizesHiddenClassNamesFromSupportedJdkFormats() {
    assertThat(
            Stream.of("example.Hidden/0x1234", "example.Hidden+0x1234.567890")
                .map(TraceClassName::isHidden))
        .containsOnly(true);
  }

  @Test
  void keepsOrdinaryNamesAndRejectsMalformedHiddenSuffixes() {
    assertThat(
            Stream.of("example.Hidden", "example.Hidden+0x", "example.Hidden+0x1234.x")
                .map(TraceClassName::isHidden))
        .containsOnly(false);
  }
}
