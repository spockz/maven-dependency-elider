/* WHY: Verifies HotSpot CDS list parsing, normalization, comments, and malformed-entry handling
 * hermetically. */

package io.github.spockz.elider.trace;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers HotSpot CDS list file parsing. */
@SuppressWarnings({
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.UncommentedEmptyConstructor",
  "PMD.CommentDefaultAccessModifier"
})
class CdsClassListReaderTest {
  /** Supplies isolated input paths for each test. */
  @TempDir Path tempDir;

  /** Creates a package-visible test instance for JUnit. */
  CdsClassListReaderTest() {}

  @Test
  void readsSlashNamesAndSkipsCommentsAndWhitespace() throws IOException {
    final Path list = tempDir.resolve("classes.lst");
    Files.writeString(
        list,
        "# generated class list\n@from-source\n\n  java/lang/Object  \n"
            + "org/apache/commons/codec/binary/Base64\nexample/Éclair\n");

    final TraceData result = new CdsClassListReader().read(list);

    assertThat(result.loadedClassesSlashFormat())
        .containsExactlyInAnyOrder(
            "java/lang/Object", "org/apache/commons/codec/binary/Base64", "example/Éclair");
    assertThat(result.loadedClassesDotFormat()).contains("java.lang.Object", "example.Éclair");
  }

  @Test
  void rejectsMalformedEntriesAndUnsupportedFiles() throws IOException {
    final Path malformed = tempDir.resolve("malformed.lst");
    Files.writeString(malformed, "java/lang/Object extra\n");
    final CdsClassListReader reader = new CdsClassListReader();

    assertThatIOException().isThrownBy(() -> reader.read(malformed));
    assertThatIOException().isThrownBy(() -> reader.read(tempDir.resolve("trace.log")));
  }

  @Test
  void propagatesUnreadableFiles() {
    final Path missing = tempDir.resolve("missing.lst");

    assertThatIOException().isThrownBy(() -> new CdsClassListReader().read(missing));
  }
}
