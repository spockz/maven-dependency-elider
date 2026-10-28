/* WHY: Shares small graph and trim-record builders across mediated report tests. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;

/** Test fixtures for mediated report paths. */
@SuppressWarnings(
    "PMD.CommentDefaultAccessModifier") // Helpers are shared only within this test package.
final class MediatedGraphReportTestSupport {
  /** Number of components in the synthetic project identity accepted by test nodes. */
  private static final int PROJECT_GAV_PART_COUNT = 3;

  /** Deterministic source digests accepted by trim records. */
  private static final String TEST_DIGEST_256 = "a".repeat(64);

  /** Deterministic SHA-1 value accepted by trim records. */
  private static final String TEST_DIGEST_1 = "b".repeat(40);

  private MediatedGraphReportTestSupport() {
    throw new AssertionError("No instances");
  }

  static MediatedGraphReport report(
      final DependencyNode root,
      final ElisionDecision decision,
      final List<ArtifactTrimRecord> trims)
      throws java.io.IOException {
    return report(root, decision, trims, "fixture:consumer:1.0");
  }

  static MediatedGraphReport report(
      final DependencyNode root,
      final ElisionDecision decision,
      final List<ArtifactTrimRecord> trims,
      final String projectGav)
      throws java.io.IOException {
    final ResolverArtifactGraphCapturePair pair =
        EffectiveGraphPolicyTestSupport.pair(root, root, "report-capture");
    final EffectiveGraphPolicy.Evaluation evaluation =
        EffectiveGraphPolicy.evaluatePair(pair, decision);
    return MediatedGraphReport.create(
        pair, evaluation, evaluation.elidedArtifacts(), trims, projectGav);
  }

  static MediatedGraphReport reportForOutputs(
      final ArtifactCoordinate dropped, final ArtifactCoordinate trimmed, final String projectGav)
      throws java.io.IOException {
    final DependencyNode root = projectNode(projectGav);
    root.setChildren(List.of(node(dropped), node(trimmed)));
    return report(
        root, decision(Set.of(trimmed), Set.of(dropped)), List.of(trimRecord(trimmed)), projectGav);
  }

  static MediatedGraphReport reportForDroppedOutput(
      final ArtifactCoordinate dropped, final String projectGav) throws java.io.IOException {
    final DependencyNode root = projectNode(projectGav);
    root.setChildren(List.of(node(dropped)));
    return report(root, decision(Set.of(), Set.of(dropped)), List.of(), projectGav);
  }

  static MediatedGraphReport emptyGraph(final String projectGav) throws java.io.IOException {
    return report(projectNode(projectGav), decision(Set.of(), Set.of()), List.of(), projectGav);
  }

  private static DependencyNode projectNode(final String projectGav) {
    final String[] parts = projectGav.split(":", -1);
    if (parts.length != PROJECT_GAV_PART_COUNT) {
      throw new IllegalArgumentException("Project GAV must have three components");
    }
    return new DefaultDependencyNode(
        new Dependency(
            new DefaultArtifact(parts[0], parts[1], "", "pom", parts[2]), "compile", false));
  }

  private static DependencyNode node(final ArtifactCoordinate coordinate) {
    return new DefaultDependencyNode(
        new Dependency(
            new DefaultArtifact(
                coordinate.groupId(),
                coordinate.artifactId(),
                coordinate.classifier(),
                coordinate.type(),
                coordinate.version()),
            coordinate.scope(),
            false));
  }

  static ArtifactTrimRecord trimRecord(final ArtifactCoordinate coordinate) {
    return new ArtifactTrimRecord(
        coordinate,
        Path.of("original.jar"),
        TEST_DIGEST_256,
        TEST_DIGEST_1,
        Path.of("trimmed.jar"),
        "c".repeat(64),
        "d".repeat(40),
        4,
        3,
        128L);
  }

  static ElisionDecision decision(
      final Set<ArtifactCoordinate> retained, final Set<ArtifactCoordinate> dropped) {
    return new ElisionDecision(retained, dropped, Map.of(), Map.of(), 0L);
  }
}
