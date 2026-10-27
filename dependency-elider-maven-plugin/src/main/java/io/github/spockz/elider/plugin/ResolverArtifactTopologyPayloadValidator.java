/* WHY: Checks graph roots, reachability, edges, and winner references after node decoding. */

package io.github.spockz.elider.plugin;

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

/** Validates topological references in a captured graph. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactTopologyPayloadValidator {
  private ResolverArtifactTopologyPayloadValidator() {
    throw new AssertionError("No instances");
  }

  static void validate(
      final Object rootValue, final List<?> edgeValues, final Map<String, Map<?, ?>> nodes) {
    final String rootId = validateRoot(rootValue, nodes);
    validateEdges(edgeValues, nodes);
    validateReachability(rootId, edgeValues, nodes);
    validateWinnerReferences(nodes);
  }

  private static String validateRoot(final Object rootValue, final Map<String, Map<?, ?>> nodes) {
    if (rootValue == null) {
      if (!nodes.isEmpty()) {
        throw ResolverArtifactGraphPayloadChecks.invalid("null graph root must have no nodes");
      }
      return null;
    }
    final String rootId = ResolverArtifactGraphPayloadChecks.nodeId(rootValue, "root node ID");
    final Map<?, ?> root = nodes.get(rootId);
    if (root == null
        || !Boolean.TRUE.equals(root.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))) {
      throw ResolverArtifactGraphPayloadChecks.invalid("root must refer to a reachable node");
    }
    return rootId;
  }

  private static void validateEdges(final List<?> values, final Map<String, Map<?, ?>> nodes) {
    for (final Object value : values) {
      final Map<?, ?> edge = ResolverArtifactGraphPayloadChecks.map(value, "edge");
      ResolverArtifactGraphPayloadChecks.fields(
          edge, ResolverArtifactGraphSnapshotSchema.EDGE_FIELDS, "edge");
      final String parentId =
          ResolverArtifactGraphPayloadChecks.nodeId(
              edge.get(ResolverArtifactGraphSnapshotSchema.PARENT_NODE_ID), "edge parent ID");
      if (!reachableNode(parentId, nodes)) {
        throw ResolverArtifactGraphPayloadChecks.invalid("edge parent must be reachable");
      }
      final Object childValue = edge.get(ResolverArtifactGraphSnapshotSchema.CHILD_NODE_ID);
      if (childValue != null) {
        final String childId =
            ResolverArtifactGraphPayloadChecks.nodeId(childValue, "edge child ID");
        if (!reachableNode(childId, nodes)) {
          throw ResolverArtifactGraphPayloadChecks.invalid("edge child must be reachable");
        }
      }
    }
  }

  private static void validateReachability(
      final String rootId, final List<?> edges, final Map<String, Map<?, ?>> nodes) {
    final Set<String> reachable = reachableNodes(rootId, edges);
    nodes.forEach(
        (id, node) -> {
          if (reachable.contains(id)
              != Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))) {
            throw ResolverArtifactGraphPayloadChecks.invalid(
                "node reachability does not match graph edges");
          }
        });
  }

  private static Set<String> reachableNodes(final String rootId, final List<?> edges) {
    // ArrayDeque provides FIFO traversal required to validate the stored graph order.
    final Set<String> reachable = new HashSet<>();
    final Queue<String> queue = new ArrayDeque<>();
    if (rootId != null) {
      queue.add(rootId);
    }
    while (!queue.isEmpty()) {
      final String parentId = queue.remove();
      if (reachable.add(parentId)) {
        enqueueChildren(parentId, edges, queue);
      }
    }
    return reachable;
  }

  private static void enqueueChildren(
      final String parentId, final List<?> edges, final Queue<String> queue) {
    for (final Object edgeValue : edges) {
      final Map<?, ?> edge = (Map<?, ?>) edgeValue;
      if (parentId.equals(edge.get(ResolverArtifactGraphSnapshotSchema.PARENT_NODE_ID))
          && edge.get(ResolverArtifactGraphSnapshotSchema.CHILD_NODE_ID) != null) {
        queue.add((String) edge.get(ResolverArtifactGraphSnapshotSchema.CHILD_NODE_ID));
      }
    }
  }

  private static boolean reachableNode(final String nodeId, final Map<String, Map<?, ?>> nodes) {
    final Map<?, ?> node = nodes.get(nodeId);
    return node != null
        && Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE));
  }

  private static void validateWinnerReferences(final Map<String, Map<?, ?>> nodes) {
    nodes.forEach(
        (id, node) -> {
          final Object winnerValue =
              node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_NODE_ID);
          if (winnerValue != null && !nodes.containsKey(winnerValue)) {
            throw ResolverArtifactGraphPayloadChecks.invalid(
                "conflict winner references a missing node from " + id);
          }
          if (winnerValue != null
              && node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_EXTERNAL_ARTIFACT)
                  != null) {
            throw ResolverArtifactGraphPayloadChecks.invalid(
                "conflict winner cannot be both internal and external");
          }
        });
  }
}
