/* WHY: Proves persisted report paths are shortest, stable, and occurrence-aware. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers path derivation and fail-closed graph reporting. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit owns test-instance creation.
final class MediatedGraphReportTest {
  /** Stable fake graph labels for path assertions. */
  private static final String ROOT_NODE = "root";

  /** First branch label used to test stable tie selection. */
  private static final String LEFT_NODE = "left";

  /** Second branch label used to test stable tie selection. */
  private static final String RIGHT_NODE = "right";

  /** Candidate label used in drop-path scenarios. */
  private static final String DROP_NODE = "drop";

  /** Scope used for each synthetic graph occurrence. */
  private static final String COMPILE = EffectiveGraphPolicyTestSupport.COMPILE_SCOPE;

  /** JUnit-managed directory for persisted report round-trip coverage. */
  @TempDir private Path temporaryDirectory;

  @Test
  void usesFirstShortestPathForSharedDiamondOccurrence() throws IOException {
    final DependencyNode root = EffectiveGraphPolicyTestSupport.node(ROOT_NODE);
    final DependencyNode left = EffectiveGraphPolicyTestSupport.node(LEFT_NODE);
    final DependencyNode right = EffectiveGraphPolicyTestSupport.node(RIGHT_NODE);
    final DependencyNode drop = EffectiveGraphPolicyTestSupport.node(DROP_NODE);
    left.setChildren(List.of(drop));
    right.setChildren(List.of(drop));
    root.setChildren(List.of(left, right));
    final ArtifactCoordinate leftCoordinate = coordinate(LEFT_NODE);
    final ArtifactCoordinate rightCoordinate = coordinate(RIGHT_NODE);
    final ArtifactCoordinate dropCoordinate = coordinate(DROP_NODE);

    final MediatedGraphReport report =
        MediatedGraphReportTestSupport.report(
            root,
            MediatedGraphReportTestSupport.decision(
                Set.of(leftCoordinate, rightCoordinate), Set.of(dropCoordinate)),
            List.of());

    assertThat(report.artifactPaths())
        .extracting(
            path ->
                new PathObservation(
                    path.kind(),
                    path.coordinate(),
                    path.steps().stream().map(MediatedGraphReport.PathStep::nodeId).toList()))
        .containsExactly(
            new PathObservation(
                "WHOLE_ARTIFACT_DROPPED", dropCoordinate, List.of("n0", "n1", "n3")));
  }

  @Test
  void preservesPathsForEveryRepeatedCoordinateOccurrence() throws IOException {
    final DependencyNode root = EffectiveGraphPolicyTestSupport.node(ROOT_NODE);
    final DependencyNode left = EffectiveGraphPolicyTestSupport.node(LEFT_NODE);
    final DependencyNode right = EffectiveGraphPolicyTestSupport.node(RIGHT_NODE);
    left.setChildren(List.of(EffectiveGraphPolicyTestSupport.node(DROP_NODE)));
    right.setChildren(List.of(EffectiveGraphPolicyTestSupport.node(DROP_NODE)));
    root.setChildren(List.of(left, right));
    final ArtifactCoordinate leftCoordinate = coordinate(LEFT_NODE);
    final ArtifactCoordinate rightCoordinate = coordinate(RIGHT_NODE);
    final ArtifactCoordinate dropCoordinate = coordinate(DROP_NODE);

    final MediatedGraphReport report =
        MediatedGraphReportTestSupport.report(
            root,
            MediatedGraphReportTestSupport.decision(
                Set.of(leftCoordinate, rightCoordinate), Set.of(dropCoordinate)),
            List.of());

    assertThat(report.artifactPaths())
        .filteredOn(path -> path.coordinate().equals(dropCoordinate))
        .extracting(
            path ->
                new OccurrencePath(
                    path.nodeId(),
                    path.steps().stream().map(MediatedGraphReport.PathStep::nodeId).toList()))
        .containsExactly(
            new OccurrencePath("n3", List.of("n0", "n1", "n3")),
            new OccurrencePath("n4", List.of("n0", "n2", "n4")));
  }

  @Test
  void recordsTrimmedOccurrencePathAndTerminatesOnCycles() throws IOException {
    final DependencyNode root = EffectiveGraphPolicyTestSupport.node(ROOT_NODE);
    final DependencyNode first = EffectiveGraphPolicyTestSupport.node("first");
    final DependencyNode second = EffectiveGraphPolicyTestSupport.node("second");
    first.setChildren(List.of(second));
    second.setChildren(List.of(first));
    root.setChildren(List.of(first));
    final ArtifactCoordinate firstCoordinate = coordinate("first");
    final ArtifactCoordinate secondCoordinate = coordinate("second");

    final MediatedGraphReport report =
        MediatedGraphReportTestSupport.report(
            root,
            MediatedGraphReportTestSupport.decision(
                Set.of(firstCoordinate, secondCoordinate), Set.of()),
            List.of(MediatedGraphReportTestSupport.trimRecord(secondCoordinate)));

    assertThat(report.artifactPaths())
        .extracting(
            path ->
                new PathObservation(
                    path.kind(),
                    path.coordinate(),
                    path.steps().stream().map(MediatedGraphReport.PathStep::nodeId).toList()))
        .containsExactly(
            new PathObservation("CLASS_TRIMMED", secondCoordinate, List.of("n0", "n1", "n2")));
  }

  @Test
  void retainsWinnerReferencesAndProtectedReason() throws IOException {
    final DependencyNode root = EffectiveGraphPolicyTestSupport.node(ROOT_NODE);
    final DependencyNode candidate = EffectiveGraphPolicyTestSupport.node(DROP_NODE);
    candidate.setData(
        org.eclipse.aether.util.graph.transformer.ConflictResolver.NODE_DATA_WINNER,
        EffectiveGraphPolicyTestSupport.node("winner"));
    root.setChildren(List.of(candidate));
    final ArtifactCoordinate drop = coordinate("drop");
    final MediatedGraphReport report =
        MediatedGraphReportTestSupport.report(
            root, MediatedGraphReportTestSupport.decision(Set.of(), Set.of(drop)), List.of());

    assertThat(
            List.of(
                report.snapshot().nodes().size(),
                report.snapshot().nodes().get(1).get("conflictWinnerNodeId"),
                report.nodeStatuses().get(1).disposition(),
                report.nodeStatuses().get(1).protectionReason(),
                report.artifactPaths().size()))
        .containsExactly(3, "n2", "PROTECTED", "conflict winner metadata is present", 0);
  }

  @Test
  void unavailableGraphCarriesReasonWithoutInventedPaths() {
    final MediatedGraphReport report =
        MediatedGraphReport.unavailable("No unique TEST graph matched the Maven inventory");

    assertThat(report.toString())
        .contains("available=false", "No unique TEST graph", "snapshot=null", "artifactPaths=[]");
  }

  @Test
  void persistsGraphOccurrencesAndPathsThroughJsonRoundTrip() throws IOException {
    final DependencyNode root = EffectiveGraphPolicyTestSupport.node(ROOT_NODE);
    final DependencyNode droppedNode = EffectiveGraphPolicyTestSupport.node(DROP_NODE);
    root.setChildren(List.of(droppedNode));
    final ArtifactCoordinate dropped = coordinate("drop");
    final MediatedGraphReport graph =
        MediatedGraphReportTestSupport.report(
            root, MediatedGraphReportTestSupport.decision(Set.of(), Set.of(dropped)), List.of());
    final MavenElisionReportSnapshot snapshot =
        new MavenElisionReportSnapshot(
            MavenElisionReportSnapshot.SCHEMA_VERSION,
            "fixture",
            "consumer",
            "1.0",
            Files.createDirectories(temporaryDirectory).toRealPath().toString(),
            "2026-10-28T00:00:00Z",
            1,
            2048,
            List.of(new MavenElisionReportSnapshot.DroppedArtifact(dropped.toString(), 2048)),
            List.of(dropped.toString()),
            0,
            0,
            List.of(),
            graph);
    final Path reportFile = temporaryDirectory.resolve("report.json");

    MavenElisionReportWriter.write(reportFile, snapshot);

    final MavenElisionReportSnapshot restored = MavenElisionReportWriter.read(reportFile);
    assertThat(restored).isEqualTo(snapshot);
  }

  @Test
  void rejectsBoundTrimWithoutMatchingGraphOccurrence() {
    final DependencyNode root = EffectiveGraphPolicyTestSupport.node("root");
    final ArtifactCoordinate retained = coordinate("retained");
    root.setChildren(List.of(EffectiveGraphPolicyTestSupport.node("retained")));
    final ArtifactCoordinate missing = coordinate("missing");
    final ResolverArtifactGraphCapturePair pair =
        EffectiveGraphPolicyTestSupport.pair(root, root, "report-capture");
    final EffectiveGraphPolicy.Evaluation evaluation =
        EffectiveGraphPolicy.evaluatePair(
            pair, MediatedGraphReportTestSupport.decision(Set.of(retained), Set.of()));

    assertThatThrownBy(
            () ->
                MediatedGraphReport.create(
                    pair,
                    evaluation,
                    evaluation.elidedArtifacts(),
                    List.of(MediatedGraphReportTestSupport.trimRecord(missing)),
                    "fixture:consumer:1.0"))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("no dependency path for every effective output");
  }

  private static ArtifactCoordinate coordinate(final String artifactId) {
    return EffectiveGraphPolicyTestSupport.coordinate(artifactId, COMPILE);
  }

  private record OccurrencePath(String nodeId, List<String> steps) {}

  private record PathObservation(
      String kind, ArtifactCoordinate coordinate, List<String> stepNodeIds) {}
}
