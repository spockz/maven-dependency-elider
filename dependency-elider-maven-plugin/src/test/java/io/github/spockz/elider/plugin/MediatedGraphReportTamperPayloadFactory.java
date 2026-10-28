// WHY: Builds valid persisted graphs so tamper tests alter only the invariant under test.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.eclipse.aether.graph.DependencyNode;

/** Factories for valid reports used as persisted tampering inputs. */
@SuppressWarnings(
    "PMD.CommentDefaultAccessModifier") // Test helper is package-local infrastructure.
final class MediatedGraphReportTamperPayloadFactory {
  /** Serializes JSON using the same defaults as the report writer. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Project identity used by the synthetic report graph. */
  private static final String PROJECT_GAV = "fixture:consumer:1.0";

  /** Project group stored in the synthetic snapshots. */
  private static final String PROJECT_GROUP = "fixture";

  /** Project artifact stored in the synthetic snapshots. */
  private static final String PROJECT_ARTIFACT = "consumer";

  /** Project version stored in the synthetic snapshots. */
  private static final String PROJECT_VERSION = "1.0";

  /** Timestamp used by the valid source payloads. */
  private static final String GENERATED_AT = "2026-10-28T00:00:00Z";

  private MediatedGraphReportTamperPayloadFactory() {
    throw new AssertionError("No instances");
  }

  static ObjectNode payload(final Path directory, final boolean longerAlternative)
      throws IOException {
    final DependencyNode root = EffectiveGraphPolicyTestSupport.node("root");
    final DependencyNode dropped = EffectiveGraphPolicyTestSupport.node("drop");
    final DependencyNode retained = EffectiveGraphPolicyTestSupport.node("retained");
    if (longerAlternative) {
      final DependencyNode left = EffectiveGraphPolicyTestSupport.node("left");
      left.setChildren(List.of(dropped));
      root.setChildren(List.of(left, dropped, retained));
    } else {
      root.setChildren(List.of(dropped, retained));
    }
    final ArtifactCoordinate droppedCoordinate =
        MediatedGraphReportTamperTestSupport.coordinate("drop");
    final ArtifactCoordinate retainedCoordinate =
        MediatedGraphReportTamperTestSupport.coordinate("retained");
    final MediatedGraphReport graph =
        MediatedGraphReportTestSupport.report(
            root,
            MediatedGraphReportTestSupport.decision(
                Set.of(retainedCoordinate), Set.of(droppedCoordinate)),
            List.of(MediatedGraphReportTestSupport.trimRecord(retainedCoordinate)));
    final MavenElisionReportSnapshot.TrimmedArtifact trim =
        new MavenElisionReportSnapshot.TrimmedArtifact(retainedCoordinate.toString(), 1, 32);
    final MavenElisionReportSnapshot snapshot =
        new MavenElisionReportSnapshot(
            MavenElisionReportSnapshot.SCHEMA_VERSION,
            PROJECT_GROUP,
            PROJECT_ARTIFACT,
            PROJECT_VERSION,
            Files.createDirectories(directory).toRealPath().toString(),
            GENERATED_AT,
            1,
            12,
            List.of(
                new MavenElisionReportSnapshot.DroppedArtifact(droppedCoordinate.toString(), 12)),
            List.of(droppedCoordinate.toString()),
            trim.programClassesPruned(),
            trim.uncompressedProgramClassBytesPruned(),
            List.of(trim),
            graph);
    return payloadFromSnapshot(directory, snapshot);
  }

  static ObjectNode unavailablePayload(final Path directory) throws IOException {
    final MavenElisionReportSnapshot snapshot =
        new MavenElisionReportSnapshot(
            MavenElisionReportSnapshot.SCHEMA_VERSION,
            PROJECT_GROUP,
            PROJECT_ARTIFACT,
            PROJECT_VERSION,
            Files.createDirectories(directory).toRealPath().toString(),
            GENERATED_AT,
            0,
            0,
            List.of(),
            List.of(),
            0,
            0,
            List.of(),
            MediatedGraphReport.unavailable("No compatible graph was captured"));
    return payloadFromSnapshot(directory, snapshot);
  }

  static ObjectNode emptyOutputPayload(final Path directory) throws IOException {
    final MavenElisionReportSnapshot snapshot =
        new MavenElisionReportSnapshot(
            MavenElisionReportSnapshot.SCHEMA_VERSION,
            PROJECT_GROUP,
            PROJECT_ARTIFACT,
            PROJECT_VERSION,
            Files.createDirectories(directory).toRealPath().toString(),
            GENERATED_AT,
            0,
            0,
            List.of(),
            List.of(),
            0,
            0,
            List.of(),
            MediatedGraphReportTestSupport.emptyGraph(PROJECT_GAV));
    return payloadFromSnapshot(directory, snapshot);
  }

  private static ObjectNode payloadFromSnapshot(
      final Path directory, final MavenElisionReportSnapshot snapshot) throws IOException {
    final Path reportFile = directory.resolve("source-report.json");
    MavenElisionReportWriter.write(reportFile, snapshot);
    return (ObjectNode) JSON.readTree(reportFile.toFile());
  }
}
