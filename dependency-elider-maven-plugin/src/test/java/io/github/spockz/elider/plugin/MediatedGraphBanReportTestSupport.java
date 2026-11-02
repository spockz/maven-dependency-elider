/* WHY: Builds persisted graph outcomes that exercise policy-ban report integrity. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;

/** Creates typed mediated graph payloads for ban cross-section tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MediatedGraphBanReportTestSupport {
  /** Number of coordinate components for the synthetic project root. */
  private static final int PROJECT_GAV_PART_COUNT = 3;

  private MediatedGraphBanReportTestSupport() {
    throw new AssertionError("No instances");
  }

  static MediatedGraphReport dropped(final ArtifactCoordinate coordinate, final String projectGav)
      throws IOException {
    final DependencyNode root = projectNode(projectGav);
    root.setChildren(List.of(node(coordinate)));
    return report(root, Set.of(), Set.of(coordinate), List.of(), projectGav);
  }

  static MediatedGraphReport retained(final ArtifactCoordinate coordinate, final String projectGav)
      throws IOException {
    final DependencyNode root = projectNode(projectGav);
    root.setChildren(List.of(node(coordinate)));
    return report(root, Set.of(coordinate), Set.of(), List.of(), projectGav);
  }

  static MediatedGraphReport droppedAndRetained(
      final ArtifactCoordinate dropped, final ArtifactCoordinate retained, final String projectGav)
      throws IOException {
    final DependencyNode root = projectNode(projectGav);
    root.setChildren(List.of(node(dropped), node(retained)));
    return report(root, Set.of(retained), Set.of(dropped), List.of(), projectGav);
  }

  static MediatedGraphReport droppedAndTrimmed(
      final ArtifactCoordinate dropped, final ArtifactCoordinate trimmed, final String projectGav)
      throws IOException {
    final DependencyNode root = projectNode(projectGav);
    root.setChildren(List.of(node(dropped), node(trimmed)));
    return report(
        root,
        Set.of(trimmed),
        Set.of(dropped),
        List.of(MediatedGraphReportTestSupport.trimRecord(trimmed)),
        projectGav);
  }

  static MediatedGraphReport trimmed(final ArtifactCoordinate coordinate, final String projectGav)
      throws IOException {
    final DependencyNode root = projectNode(projectGav);
    root.setChildren(List.of(node(coordinate)));
    return report(
        root,
        Set.of(coordinate),
        Set.of(),
        List.of(MediatedGraphReportTestSupport.trimRecord(coordinate)),
        projectGav);
  }

  static MediatedGraphReport empty(final String projectGav) throws IOException {
    return report(projectNode(projectGav), Set.of(), Set.of(), List.of(), projectGav);
  }

  private static MediatedGraphReport report(
      final DependencyNode root,
      final Set<ArtifactCoordinate> retained,
      final Set<ArtifactCoordinate> dropped,
      final List<io.github.spockz.elider.trimmer.ArtifactTrimRecord> trims,
      final String projectGav)
      throws IOException {
    final ElisionDecision decision = new ElisionDecision(retained, dropped, Map.of(), Map.of(), 0L);
    return MediatedGraphReportTestSupport.report(root, decision, trims, projectGav);
  }

  private static DependencyNode projectNode(final String projectGav) {
    final String[] parts = projectGav.split(":", -1);
    if (parts.length != PROJECT_GAV_PART_COUNT) {
      throw new IllegalArgumentException("Project GAV must have three components");
    }
    return new DefaultDependencyNode(
        new Dependency(new DefaultArtifact(parts[0], parts[1], "", "pom", parts[2]), "compile"));
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
            coordinate.scope()));
  }
}
