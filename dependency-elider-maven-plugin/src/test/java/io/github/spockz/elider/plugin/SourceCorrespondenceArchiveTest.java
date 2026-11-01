// WHY: Ensures source bytes retained from archives cannot be mutated through constructor inputs
// or result accessors.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Checks that retained source bytes cannot be mutated externally. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class SourceCorrespondenceArchiveTest {
  /** Archive entry whose byte array is checked at both ownership boundaries. */
  private static final String ENTRY_NAME = "A.java";

  @Test
  void sourceBytesAreDefensivelyCopiedAtConstructionAndAccess() {
    final byte[] original = {1, 2, 3};
    final SourceCorrespondenceArchive archive =
        new SourceCorrespondenceArchive(
            "sha", Map.of(ENTRY_NAME, original), List.of(), List.of(ENTRY_NAME));
    original[0] = 9;
    final byte[] returned = archive.sourceContent(ENTRY_NAME);
    returned[1] = 8;

    assertThat(archive.sourceContent(ENTRY_NAME)).containsExactly(1, 2, 3);
  }
}
