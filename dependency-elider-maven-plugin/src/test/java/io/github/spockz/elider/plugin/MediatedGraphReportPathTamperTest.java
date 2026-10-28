// WHY: Rejects forged graph occurrence paths and output labels from persisted reports.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers path coordinate, status, kind, and shortest-walk tampering. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit owns test-instance creation.
final class MediatedGraphReportPathTamperTest {
  /** JSON field holding a path's target coordinate. */
  private static final String COORDINATE_FIELD = "coordinate";

  /** JSON field holding an occurrence's node identifier. */
  private static final String NODE_ID_FIELD = "nodeId";

  /** Persisted class-trimming path kind used to target output rows. */
  private static final String TRIMMED = MediatedGraphReportTamperTestSupport.trimmedKind();

  /** Temporary root for serialized tampering fixtures. */
  @TempDir private Path temporaryDirectory;

  @Test
  void rejectsForgedTargetCoordinate() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.payload(temporaryDirectory, false);
    MediatedGraphReportTamperTestSupport.firstPath(payload)
        .with(COORDINATE_FIELD)
        .put("artifactId", "forged");

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  @Test
  void rejectsDispositionThatDisagreesWithCapturedNode() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.payload(temporaryDirectory, false);
    MediatedGraphReportTamperTestSupport.firstPath(payload).put("disposition", "RETAINED");

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  @Test
  void rejectsForgedRootStepLabel() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.payload(temporaryDirectory, false);
    final ArrayNode steps =
        MediatedGraphReportTamperTestSupport.firstPath(payload).withArray("steps");
    ((ObjectNode) steps.get(0)).put(COORDINATE_FIELD, "forged:project:1.0");

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  @Test
  void rejectsOutputKindThatDisagreesWithDisposition() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.payload(temporaryDirectory, false);
    MediatedGraphReportTamperTestSupport.firstPath(payload).put("kind", TRIMMED);

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  @Test
  void rejectsUnknownDispositionWhenPathAndNodeLabelsAreBothChanged() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.payload(temporaryDirectory, false);
    final ObjectNode artifactPath =
        MediatedGraphReportTamperTestSupport.pathOfKind(payload, TRIMMED);
    artifactPath.put("disposition", "BOGUS");
    final String targetNodeId = artifactPath.path(NODE_ID_FIELD).asText();
    final ArrayNode statuses = (ArrayNode) payload.path("mediatedGraph").path("nodeStatuses");
    for (final JsonNode status : statuses) {
      if (targetNodeId.equals(status.path(NODE_ID_FIELD).asText())) {
        ((ObjectNode) status).put("disposition", "BOGUS");
        break;
      }
    }

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }

  @Test
  void rejectsLongerValidWalkInsteadOfCanonicalShortestPath() throws IOException {
    final ObjectNode payload =
        MediatedGraphReportTamperPayloadFactory.payload(temporaryDirectory, true);
    final ArrayNode steps =
        MediatedGraphReportTamperTestSupport.firstPath(payload).withArray("steps");
    steps.removeAll();
    steps
        .addObject()
        .put(NODE_ID_FIELD, "n0")
        .put(COORDINATE_FIELD, "fixture:root:jar:1.0 (compile)");
    steps
        .addObject()
        .put(NODE_ID_FIELD, "n1")
        .put(COORDINATE_FIELD, "fixture:left:jar:1.0 (compile)");
    steps
        .addObject()
        .put(NODE_ID_FIELD, "n2")
        .put(COORDINATE_FIELD, "fixture:drop:jar:1.0 (compile)");

    MediatedGraphReportTamperTestSupport.assertRejected(temporaryDirectory, payload);
  }
}
