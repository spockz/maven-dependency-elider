// WHY: Rejects persisted output totals that do not match graph occurrence coverage.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers persisted graph/output completeness and fail-closed consistency. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit owns test-instance creation.
final class MediatedGraphReportCoverageTamperTest {
  /** Persisted whole-artifact disposition path kind. */
  private static final String DROPPED = MediatedGraphReportTamperTestSupport.droppedKind();

  /** Persisted class-trimming path kind. */
  private static final String TRIMMED = MediatedGraphReportTamperTestSupport.trimmedKind();

  /** Temporary root for serialized tampering fixtures. */
  @TempDir private Path temporaryDirectory;

  @Test
  void rejectsMissingDroppedPath() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.payload(temporaryDirectory, false);
    MediatedGraphReportTamperTestSupport.paths(payload).remove(0);

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  @Test
  void rejectsMissingTrimmedPath() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.payload(temporaryDirectory, false);
    removePath(payload, TRIMMED);

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  @Test
  void rejectsEffectiveDropWhenGraphIsUnavailable() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.unavailablePayload(temporaryDirectory);
    payload.put("wholeArtifactsDropped", 1);
    payload.put("originalJarBytesDropped", 12);
    payload
        .putArray("droppedArtifacts")
        .addObject()
        .put("coordinate", MediatedGraphReportTamperTestSupport.coordinate("drop").toString())
        .put("originalJarBytes", 12);

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  @Test
  void rejectsRemovingDropPathAndTotalsWhileSafeElidedStatusRemains() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.payload(temporaryDirectory, false);
    removePath(payload, DROPPED);
    payload.put("wholeArtifactsDropped", 0);
    payload.put("originalJarBytesDropped", 0);
    payload.putArray("droppedArtifacts");

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  @Test
  void rejectsProjectRootAsSafeElidedWithoutOutputRows() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.emptyOutputPayload(temporaryDirectory);
    final ObjectNode graph = (ObjectNode) payload.path("mediatedGraph");
    final String rootId = graph.path("snapshot").path("rootNodeId").asText();
    final ArrayNode statuses = (ArrayNode) graph.path("nodeStatuses");
    for (int index = 0; index < statuses.size(); index++) {
      final ObjectNode status = (ObjectNode) statuses.get(index);
      if (rootId.equals(status.path("nodeId").asText())) {
        status.put("disposition", "SAFE_ELIDED");
        break;
      }
    }

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  private static void removePath(final ObjectNode payload, final String kind) {
    final ArrayNode paths = MediatedGraphReportTamperTestSupport.paths(payload);
    for (int index = 0; index < paths.size(); index++) {
      if (kind.equals(paths.get(index).path("kind").asText())) {
        paths.remove(index);
        return;
      }
    }
  }
}
