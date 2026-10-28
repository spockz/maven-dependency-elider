/* WHY: Rejects forged node outcomes before they can justify persisted output paths. */

package io.github.spockz.elider.plugin;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Validates per-node policy dispositions against the captured graph. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal report validation helper.
final class MediatedGraphReportNodeStatusValidator {
  private MediatedGraphReportNodeStatusValidator() {
    throw new AssertionError("No instances");
  }

  static void validate(
      final ResolverArtifactGraphSnapshot snapshot,
      final List<MediatedGraphReport.NodeStatus> nodeStatuses) {
    final Set<String> nodeIds = nodeIds(snapshot);
    final List<String> statusIds =
        nodeStatuses.stream().map(MediatedGraphReport.NodeStatus::nodeId).toList();
    if (!matchesExactly(nodeIds, statusIds)) {
      throw new IllegalArgumentException("Graph report node statuses do not match the snapshot");
    }
    final Map<String, MediatedGraphReport.NodeStatus> statusesById = statusesById(nodeStatuses);
    for (final Map<String, Object> node : snapshot.nodes()) {
      validateNode(snapshot, node, statusesById);
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // This index is local to one validation call.
  private static Map<String, MediatedGraphReport.NodeStatus> statusesById(
      final List<MediatedGraphReport.NodeStatus> nodeStatuses) {
    final Map<String, MediatedGraphReport.NodeStatus> result = new java.util.HashMap<>();
    nodeStatuses.forEach(status -> result.put(status.nodeId(), status));
    return result;
  }

  private static void validateNode(
      final ResolverArtifactGraphSnapshot snapshot,
      final Map<String, Object> node,
      final Map<String, MediatedGraphReport.NodeStatus> statusesById) {
    final String nodeId = (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
    final String disposition = statusesById.get(nodeId).disposition();
    validateProjectRoot(snapshot, nodeId, disposition);
    validateReachabilityDisposition(node, disposition);
  }

  private static void validateProjectRoot(
      final ResolverArtifactGraphSnapshot snapshot, final String nodeId, final String disposition) {
    if (snapshot.rootNodeId().equals(nodeId) && !"RETAINED".equals(disposition)) {
      throw new IllegalArgumentException("Project root must have RETAINED disposition");
    }
  }

  private static void validateReachabilityDisposition(
      final Map<String, Object> node, final String disposition) {
    if (Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))) {
      validateReachableDisposition(disposition);
    } else {
      validateMetadataDisposition(disposition);
    }
  }

  private static void validateReachableDisposition(final String disposition) {
    for (final EffectiveGraphPolicy.NodeDisposition candidate :
        EffectiveGraphPolicy.NodeDisposition.values()) {
      if (candidate.name().equals(disposition)) {
        return;
      }
    }
    throw new IllegalArgumentException(
        "Reachable graph node has an unknown policy disposition: " + disposition);
  }

  private static void validateMetadataDisposition(final String disposition) {
    if (!"METADATA_ONLY".equals(disposition)) {
      throw new IllegalArgumentException(
          "Unreachable graph node must have METADATA_ONLY disposition");
    }
  }

  private static Set<String> nodeIds(final ResolverArtifactGraphSnapshot snapshot) {
    final Set<String> result = new HashSet<>();
    snapshot.nodes().stream()
        .map(node -> (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID))
        .forEach(result::add);
    return result;
  }

  private static boolean matchesExactly(final Set<String> nodeIds, final List<String> statusIds) {
    return statusIds.size() == nodeIds.size()
        && new HashSet<>(statusIds).size() == nodeIds.size()
        && nodeIds.containsAll(statusIds);
  }
}
