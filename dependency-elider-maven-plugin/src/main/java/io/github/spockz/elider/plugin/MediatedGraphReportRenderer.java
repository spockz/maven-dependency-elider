/* WHY: Renders only the graph and outcomes saved by the successful elide invocation. */

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Builds deterministic tree-like rows from the persisted mediated graph. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal report rendering helper.
final class MediatedGraphReportRenderer {
  /** Policy disposition for a node proven safe to remove. */
  private static final String SAFE_ELIDED = "SAFE_ELIDED";

  /** Policy disposition for a node protected from removal. */
  private static final String PROTECTED = "PROTECTED";

  /** Status for a retained node promoted by a reachable descendant. */
  private static final String ANCESTOR_PROMOTED = "ANCESTOR_PROMOTED";

  /** Output marker for artifacts whose classes were trimmed. */
  private static final String CLASS_TRIMMED = "CLASS_TRIMMED";

  private MediatedGraphReportRenderer() {
    throw new AssertionError("No instances");
  }

  static List<String> render(final MediatedGraphReport report, final String projectGav) {
    if (!report.available()) {
      throw new IllegalArgumentException(
          "Mediated dependency graph is unavailable: "
              + report.unavailableReason()
              + "; rerun dependency-elider:elide with the production core extension enabled");
    }
    final ResolverArtifactGraphSnapshot snapshot = report.snapshot();
    final Map<String, MediatedGraphReport.NodeStatus> statusById = statusById(report);
    final Map<String, Map<String, Object>> nodeById = nodeById(snapshot);
    final Map<String, List<String>> paths = MediatedGraphShortestPaths.from(snapshot);
    final List<String> nodeIds = reachableNodeIds(snapshot, paths);
    nodeIds.sort(pathOrder(paths, nodeById, projectGav));
    final List<String> lines = new ArrayList<>();
    lines.add("Mediated TEST dependency graph (captured and saved by the elide goal):");
    for (final String nodeId : nodeIds) {
      lines.add(
          "  - "
              + pathText(paths.get(nodeId), nodeById, projectGav)
              + " {nodeId="
              + nodeId
              + "}"
              + " ["
              + disposition(statusById.get(nodeId), isTrimmed(report, nodeId))
              + "]");
    }
    return List.copyOf(lines);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // This index is local to one render operation.
  private static Map<String, MediatedGraphReport.NodeStatus> statusById(
      final MediatedGraphReport report) {
    final Map<String, MediatedGraphReport.NodeStatus> result = new HashMap<>();
    report.nodeStatuses().forEach(status -> result.put(status.nodeId(), status));
    return result;
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Captured node order stabilizes report tie order.
  private static Map<String, Map<String, Object>> nodeById(
      final ResolverArtifactGraphSnapshot snapshot) {
    final Map<String, Map<String, Object>> result = new java.util.LinkedHashMap<>();
    snapshot.nodes().forEach(node -> result.put(nodeId(node), node));
    return result;
  }

  private static List<String> reachableNodeIds(
      final ResolverArtifactGraphSnapshot snapshot, final Map<String, List<String>> paths) {
    return snapshot.nodes().stream()
        .filter(
            node -> Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE)))
        .map(MediatedGraphReportRenderer::nodeId)
        .filter(paths::containsKey)
        .collect(java.util.stream.Collectors.toCollection(ArrayList::new));
  }

  private static Comparator<String> pathOrder(
      final Map<String, List<String>> paths,
      final Map<String, Map<String, Object>> nodes,
      final String projectGav) {
    return Comparator.comparingInt((String nodeId) -> paths.get(nodeId).size())
        .thenComparing(nodeId -> pathText(paths.get(nodeId), nodes, projectGav))
        .thenComparing(nodeId -> nodeId);
  }

  private static String pathText(
      final List<String> nodeIds,
      final Map<String, Map<String, Object>> nodes,
      final String projectGav) {
    return nodeIds.stream()
        .map(nodeId -> MediatedGraphReportPathCoordinate.display(nodes.get(nodeId), projectGav))
        .collect(java.util.stream.Collectors.joining(" -> "));
  }

  private static String disposition(
      final MediatedGraphReport.NodeStatus status, final boolean classTrimmed) {
    if (SAFE_ELIDED.equals(status.disposition())) {
      return "EFFECTIVE_DROP";
    }
    if (PROTECTED.equals(status.disposition())) {
      return classTrimmed
          ? "RETAINED, PROTECTED: " + status.protectionReason() + ", CLASS_TRIMMED"
          : "RETAINED, PROTECTED: " + status.protectionReason();
    }
    if (ANCESTOR_PROMOTED.equals(status.disposition())) {
      return classTrimmed
          ? "RETAINED, ANCESTOR_PROMOTED, CLASS_TRIMMED"
          : "RETAINED, ANCESTOR_PROMOTED";
    }
    return classTrimmed ? "RETAINED, CLASS_TRIMMED" : "RETAINED";
  }

  private static boolean isTrimmed(final MediatedGraphReport report, final String nodeId) {
    return report.artifactPaths().stream()
        .anyMatch(path -> path.nodeId().equals(nodeId) && CLASS_TRIMMED.equals(path.kind()));
  }

  private static String nodeId(final Map<String, Object> node) {
    return (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
  }
}
