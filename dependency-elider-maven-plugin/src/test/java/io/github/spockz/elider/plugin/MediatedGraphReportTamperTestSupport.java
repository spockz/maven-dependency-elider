// WHY: Shares persisted payload assertions and selectors across path and coverage tamper tests.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;

/** Selectors and loader assertions for persisted mediated-graph tampering. */
@SuppressWarnings(
    "PMD.CommentDefaultAccessModifier") // Test helper is package-local infrastructure.
final class MediatedGraphReportTamperTestSupport {
  /** Uses the report reader's default Jackson behavior. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Persisted whole-artifact disposition path kind. */
  private static final String DROPPED_KIND = "WHOLE_ARTIFACT_DROPPED";

  /** Persisted class-trimming path kind. */
  private static final String TRIMMED_KIND = "CLASS_TRIMMED";

  private MediatedGraphReportTamperTestSupport() {
    throw new AssertionError("No instances");
  }

  static void assertRejected(final Path directory, final ObjectNode payload) throws IOException {
    final Path reportFile = directory.resolve("tampered-report.json");
    JSON.writeValue(reportFile.toFile(), payload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(reportFile))
        .isInstanceOf(IOException.class);
  }

  static ArrayNode paths(final ObjectNode payload) {
    return (ArrayNode) payload.path("mediatedGraph").path("artifactPaths");
  }

  static ObjectNode firstPath(final ObjectNode payload) {
    return (ObjectNode) paths(payload).get(0);
  }

  static ObjectNode pathOfKind(final ObjectNode payload, final String kind) {
    for (final com.fasterxml.jackson.databind.JsonNode path : paths(payload)) {
      if (kind.equals(path.path("kind").asText())) {
        return (ObjectNode) path;
      }
    }
    throw new AssertionError("No path has kind " + kind);
  }

  static String droppedKind() {
    return DROPPED_KIND;
  }

  static String trimmedKind() {
    return TRIMMED_KIND;
  }

  static ArtifactCoordinate coordinate(final String artifactId) {
    return EffectiveGraphPolicyTestSupport.coordinate(
        artifactId, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
  }
}
