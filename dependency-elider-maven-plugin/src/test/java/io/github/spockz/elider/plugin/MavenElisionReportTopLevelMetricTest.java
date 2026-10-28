// WHY: Covers JSON numeric coercion risks before the immutable report record is bound.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers strict count and byte metric types in persisted report roots. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentDefaultAccessModifier"})
final class MavenElisionReportTopLevelMetricTest {
  /** Top-level whole-drop class count key. */
  private static final String DROPPED_CLASS_ENTRIES = "droppedProgramClassEntries";

  /** Top-level whole-drop class payload byte key. */
  private static final String DROPPED_CLASS_BYTES = "droppedProgramClassBytes";

  /** Top-level original JAR byte key. */
  private static final String ORIGINAL_JAR_BYTES = "originalJarBytesDropped";

  /** Top-level whole-artifact count key. */
  private static final String WHOLE_ARTIFACTS = "wholeArtifactsDropped";

  /** JSON writer for malformed report fixtures. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Temporary location for malformed report payloads. */
  @TempDir Path temporaryDirectory;

  @Test
  void rejectsNullTopLevelClassCount() throws IOException {
    assertRejected(DROPPED_CLASS_ENTRIES, payload -> payload.putNull(DROPPED_CLASS_ENTRIES));
  }

  @Test
  void rejectsNullTopLevelClassBytes() throws IOException {
    assertRejected(DROPPED_CLASS_BYTES, payload -> payload.putNull(DROPPED_CLASS_BYTES));
  }

  @Test
  void rejectsFractionalTopLevelClassBytes() throws IOException {
    assertRejected(DROPPED_CLASS_BYTES, payload -> payload.put(DROPPED_CLASS_BYTES, 0.5));
  }

  @Test
  void rejectsNegativeTopLevelJarBytes() throws IOException {
    assertRejected(ORIGINAL_JAR_BYTES, payload -> payload.put(ORIGINAL_JAR_BYTES, -1));
  }

  @Test
  void rejectsOutOfRangeTopLevelArtifactCount() throws IOException {
    assertRejected(WHOLE_ARTIFACTS, payload -> payload.put(WHOLE_ARTIFACTS, 2_147_483_648L));
  }

  @Test
  void rejectsOutOfRangeTopLevelClassBytes() throws IOException {
    assertRejected(
        DROPPED_CLASS_BYTES,
        payload -> payload.put(DROPPED_CLASS_BYTES, new BigInteger("9223372036854775808")));
  }

  private void assertRejected(final String field, final Consumer<ObjectNode> mutation)
      throws IOException {
    final ObjectNode payload = MavenElisionReportSchemaTest.currentReportShapeWithDroppedRow();
    mutation.accept(payload);
    final Path previous = temporaryDirectory.resolve("invalid-" + field + ".json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report metric must be a nonnegative integer: " + field);
  }
}
