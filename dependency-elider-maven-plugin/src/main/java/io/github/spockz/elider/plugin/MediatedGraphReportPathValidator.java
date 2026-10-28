/* WHY: Verifies each persisted path uses reachable nodes and real captured edges. */

package io.github.spockz.elider.plugin;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Validates occurrence paths against the captured mediated graph. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal path validator.
final class MediatedGraphReportPathValidator {
  private MediatedGraphReportPathValidator() {
    throw new AssertionError("No instances");
  }

  static void validate(
      final ResolverArtifactGraphSnapshot snapshot,
      final List<MediatedGraphReport.NodeStatus> nodeStatuses,
      final List<MediatedGraphReport.ArtifactPath> artifactPaths) {
    validate(snapshot, nodeStatuses, artifactPaths, null);
  }

  static void validate(
      final ResolverArtifactGraphSnapshot snapshot,
      final List<MediatedGraphReport.NodeStatus> nodeStatuses,
      final List<MediatedGraphReport.ArtifactPath> artifactPaths,
      final String projectGav) {
    final Set<String> reachable = reachableNodeIds(snapshot);
    final MediatedGraphReportPathSemanticValidator.Context semanticContext =
        MediatedGraphReportPathSemanticValidator.context(snapshot, nodeStatuses);
    for (final MediatedGraphReport.ArtifactPath path : artifactPaths) {
      validatePath(snapshot, reachable, semanticContext, projectGav, path);
    }
  }

  private static void validatePath(
      final ResolverArtifactGraphSnapshot snapshot,
      final Set<String> reachable,
      final MediatedGraphReportPathSemanticValidator.Context semanticContext,
      final String projectGav,
      final MediatedGraphReport.ArtifactPath path) {
    validatePathEndpoints(snapshot, reachable, path);
    validatePathEdges(snapshot, path);
    MediatedGraphReportPathSemanticValidator.validatePath(semanticContext, projectGav, path);
  }

  private static Set<String> reachableNodeIds(final ResolverArtifactGraphSnapshot snapshot) {
    final Set<String> reachable = new HashSet<>();
    snapshot.nodes().stream()
        .filter(
            node -> Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE)))
        .map(node -> (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID))
        .forEach(reachable::add);
    return reachable;
  }

  private static void validatePathEndpoints(
      final ResolverArtifactGraphSnapshot snapshot,
      final Set<String> reachable,
      final MediatedGraphReport.ArtifactPath path) {
    if (!reachable.contains(path.nodeId())
        || path.steps().isEmpty()
        || !path.steps().getFirst().nodeId().equals(snapshot.rootNodeId())
        || !path.steps().getLast().nodeId().equals(path.nodeId())) {
      throw new IllegalArgumentException("Graph report path is not rooted in the snapshot");
    }
  }

  private static void validatePathEdges(
      final ResolverArtifactGraphSnapshot snapshot, final MediatedGraphReport.ArtifactPath path) {
    for (int index = 1; index < path.steps().size(); index++) {
      final String parent = path.steps().get(index - 1).nodeId();
      final String child = path.steps().get(index).nodeId();
      if (!containsEdge(snapshot.edges(), parent, child)) {
        throw new IllegalArgumentException("Graph report path contains a missing edge");
      }
    }
  }

  private static boolean containsEdge(
      final List<Map<String, Object>> edges, final String parent, final String child) {
    return edges.stream().anyMatch(edge -> isEdge(edge, parent, child));
  }

  private static boolean isEdge(
      final Map<String, Object> edge, final String parent, final String child) {
    return parent.equals(edge.get(ResolverArtifactGraphSnapshotSchema.PARENT_NODE_ID))
        && child.equals(edge.get(ResolverArtifactGraphSnapshotSchema.CHILD_NODE_ID));
  }
}
