// WHY: Proves raw mediated-graph JSON cannot coerce primitive snapshot fields during binding.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers raw graph snapshot booleans and generation fields in report JSON. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentDefaultAccessModifier"})
final class MavenElisionReportGraphPayloadTest {
  /** Graph plan generation field. */
  private static final String PLAN_GENERATION = "planGeneration";

  /** Graph capture generation field. */
  private static final String CAPTURE_GENERATION = "captureGeneration";

  /** Stable prefix emitted for invalid generation-number fields. */
  private static final String NONNEGATIVE_INTEGER_PREFIX = "nonnegative integer: ";

  /** JSON serializer used to preserve malformed token types in fixtures. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Temporary directory for report payloads. */
  @TempDir Path temporaryDirectory;

  @Test
  void rejectsStringPlanPresence() throws IOException {
    final ObjectNode snapshot = validSnapshot();
    snapshot.put("planPresent", "true");

    assertRejected(snapshot, "graph planPresent must be boolean");
  }

  @Test
  void rejectsMissingPlanGeneration() throws IOException {
    final ObjectNode snapshot = validSnapshot();
    snapshot.remove(PLAN_GENERATION);

    assertRejected(snapshot, "graph snapshot fields do not match schema version 1");
  }

  @Test
  void rejectsNullPlanGeneration() throws IOException {
    final ObjectNode snapshot = validSnapshot();
    snapshot.putNull(PLAN_GENERATION);

    assertRejected(snapshot, NONNEGATIVE_INTEGER_PREFIX + PLAN_GENERATION);
  }

  @Test
  void rejectsNullCaptureGeneration() throws IOException {
    final ObjectNode snapshot = validSnapshot();
    snapshot.putNull(CAPTURE_GENERATION);

    assertRejected(snapshot, NONNEGATIVE_INTEGER_PREFIX + CAPTURE_GENERATION);
  }

  @Test
  void rejectsMissingCaptureGeneration() throws IOException {
    final ObjectNode snapshot = validSnapshot();
    snapshot.remove(CAPTURE_GENERATION);

    assertRejected(snapshot, "graph snapshot fields do not match schema version 1");
  }

  @Test
  void rejectsFractionalPlanGeneration() throws IOException {
    final ObjectNode snapshot = validSnapshot();
    snapshot.put(PLAN_GENERATION, 1.5);

    assertRejected(snapshot, NONNEGATIVE_INTEGER_PREFIX + PLAN_GENERATION);
  }

  @Test
  void rejectsFractionalCaptureGeneration() throws IOException {
    final ObjectNode snapshot = validSnapshot();
    snapshot.put(CAPTURE_GENERATION, 1.5);

    assertRejected(snapshot, NONNEGATIVE_INTEGER_PREFIX + CAPTURE_GENERATION);
  }

  private void assertRejected(final ObjectNode snapshot, final String message) throws IOException {
    final ObjectNode payload = MavenElisionReportSchemaTest.currentReportShapeWithDroppedRow();
    populateAvailableGraph((ObjectNode) payload.get("mediatedGraph"), snapshot);
    final Path previous = temporaryDirectory.resolve("invalid-graph-payload.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(message);
  }

  private static ObjectNode validSnapshot() {
    final ObjectNode snapshot = JSON.createObjectNode();
    snapshot.put("graphFingerprint", "fingerprint");
    snapshot.put("projectKey", "example:consumer:1.0");
    snapshot.put("planPresent", true);
    snapshot.putNull("planFingerprint");
    snapshot.put(PLAN_GENERATION, 1);
    snapshot.put(CAPTURE_GENERATION, 1);
    snapshot.put("rootNodeId", "n0");
    snapshot.putArray("nodes");
    snapshot.putArray("edges");
    return snapshot;
  }

  private static void populateAvailableGraph(final ObjectNode graph, final ObjectNode snapshot) {
    graph.put("available", true);
    graph.putNull("unavailableReason");
    graph.put("captureToken", "capture");
    graph.put("projectKey", "example:consumer:1.0");
    graph.put("beforeFingerprint", "before");
    graph.set("snapshot", snapshot);
    graph.putArray("nodeStatuses");
    graph.putArray("artifactPaths");
  }
}
