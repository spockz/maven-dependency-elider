// WHY: Verifies unsupported and incompatible persisted report drafts fail before deserialization.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers report schema-version and exact-field rejection. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.TooManyMethods",
  "PMD.AvoidDuplicateLiterals"
})
final class MavenElisionReportSchemaTest {
  /** Dropped-row collection key. */
  private static final String DROPPED_ROWS = "droppedArtifacts";

  /** Removed class count key on a whole-artifact row. */
  private static final String DROPPED_CLASSES = "programClassesRemoved";

  /** Removed class payload byte key on a whole-artifact row. */
  private static final String DROPPED_CLASS_BYTES = "uncompressedProgramClassBytesRemoved";

  /** Retained-JAR pruned class count key. */
  private static final String TRIMMED_CLASSES = "programClassesPruned";

  /** Retained-JAR pruned class payload byte key. */
  private static final String TRIMMED_CLASS_BYTES = "uncompressedProgramClassBytesPruned";

  /** JSON builder for adversarial report drafts. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Temporary report directory. */
  @TempDir Path temporaryDirectory;

  @Test
  void rejectsUnsupportedNonOneSnapshotWithRerunGuidance() throws IOException {
    final Path previous = temporaryDirectory.resolve("previous-report.json");
    java.nio.file.Files.writeString(previous, "{\"schemaVersion\":4}");

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported elision report schema version 4")
        .hasMessageContaining("run dependency-elider:elide");
  }

  @Test
  void rejectsSchemaOneDraftWithIncompatibleTopLevelFields() throws IOException {
    final Path previous = temporaryDirectory.resolve("incompatible-report-draft.json");
    java.nio.file.Files.writeString(previous, "{\"schemaVersion\":1,\"projectGroupId\":\"draft\"}");

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report fields do not match schema version 1")
        .hasMessageContaining("run dependency-elider:elide");
  }

  @Test
  void rejectsSchemaOneDroppedArtifactDraftMissingClassMetrics() throws IOException {
    final ObjectNode payload = currentReportShapeWithLegacyDroppedRow();
    final Path previous = temporaryDirectory.resolve("legacy-dropped-row.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report artifact row fields do not match schema version 1")
        .hasMessageContaining("run dependency-elider:elide");
  }

  @Test
  void rejectsNullDroppedArtifactClassMetrics() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.putNull(DROPPED_CLASSES);
    row.putNull(DROPPED_CLASS_BYTES);
    final Path previous = temporaryDirectory.resolve("null-dropped-metrics.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report artifact metric must be a nonnegative integer");
  }

  @Test
  void rejectsStringDroppedArtifactClassCount() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.put(DROPPED_CLASSES, "0");
    row.put(DROPPED_CLASS_BYTES, 0);
    final Path previous = temporaryDirectory.resolve("wrong-type-dropped-metrics.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("nonnegative integer: programClassesRemoved");
  }

  @Test
  void rejectsOutOfRangeDroppedArtifactClassCount() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.put(DROPPED_CLASSES, 2_147_483_648L);
    final Path previous = temporaryDirectory.resolve("out-of-range-dropped-count.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("nonnegative integer: programClassesRemoved");
  }

  @Test
  void rejectsNullTrimmedArtifactClassCount() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode trimmed =
        payload
            .withArray("trimmedArtifacts")
            .addObject()
            .put("coordinate", "example:trimmed:jar:1.0")
            .put(TRIMMED_CLASSES, 1)
            .put(TRIMMED_CLASS_BYTES, 10);
    trimmed.putNull(TRIMMED_CLASSES);
    final Path previous = temporaryDirectory.resolve("null-trimmed-metric.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("nonnegative integer: programClassesPruned");
  }

  @Test
  void rejectsNonTextArtifactCoordinate() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("trimmedArtifacts")
        .addObject()
        .put("coordinate", 7)
        .put(TRIMMED_CLASSES, 1)
        .put(TRIMMED_CLASS_BYTES, 10);
    final Path previous = temporaryDirectory.resolve("non-text-coordinate.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact coordinate must be nonblank text");
  }

  @Test
  void rejectsNonArrayCveComponents() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.put("removedCveComponents", "not-an-array");
    final Path previous = temporaryDirectory.resolve("non-array-cve.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report CVE rows must be arrays");
  }

  @Test
  void rejectsMalformedCveId() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("removedCveComponents")
        .addObject()
        .put("cveId", "INVALID-CVE")
        .put("coordinate", "example:dep:jar:1.0");
    final Path previous = temporaryDirectory.resolve("malformed-cve-id.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("cveId must be a valid CVE identifier");
  }

  @Test
  void rejectsBlankCveCoordinate() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("provenAbsentCves")
        .addObject()
        .put("cveId", "CVE-2026-10001")
        .put("coordinate", "   ");
    final Path previous = temporaryDirectory.resolve("blank-cve-coordinate.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("coordinate must be nonblank text");
  }

  private static ObjectNode currentReportShapeWithLegacyDroppedRow() {
    final ObjectNode payload = JSON.createObjectNode();
    payload.put("schemaVersion", 1);
    payload.put("projectGroupId", "example");
    payload.put("projectArtifactId", "consumer");
    payload.put("projectVersion", "1.0");
    payload.put("projectBaseDirectory", "/tmp/consumer");
    payload.put("generatedAt", "2026-10-28T00:00:00Z");
    payload.put("wholeArtifactsDropped", 1);
    payload.put("originalJarBytesDropped", 1);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    payload
        .putArray(DROPPED_ROWS)
        .addObject()
        .put("coordinate", "example:old:jar:1.0")
        .put("originalJarBytes", 1);
    payload.putArray("rawDroppedCoordinates");
    payload.put("programClassesPruned", 0);
    payload.put("uncompressedProgramClassBytesPruned", 0);
    payload.putArray("trimmedArtifacts");
    payload.putArray("removedCveComponents");
    payload.putArray("provenAbsentCves");
    final ObjectNode graph = payload.putObject("mediatedGraph");
    graph.put("available", false);
    graph.put("unavailableReason", "No graph was provided");
    graph.putNull("captureToken");
    graph.putNull("projectKey");
    graph.putNull("beforeFingerprint");
    graph.putNull("snapshot");
    graph.putArray("nodeStatuses");
    graph.putArray("artifactPaths");
    return payload;
  }

  static ObjectNode currentReportShapeWithDroppedRow() {
    final ObjectNode payload = currentReportShapeWithLegacyDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.put(DROPPED_CLASSES, 0);
    row.put(DROPPED_CLASS_BYTES, 0);
    return payload;
  }
}
