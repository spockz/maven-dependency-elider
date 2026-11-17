// WHY: Serializes projected node and edge rows in the canonical traversal order.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Builds detached node and edge payloads for an occurrence-level projection. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphProjectionPayload {
  private ResolverArtifactGraphProjectionPayload() {
    throw new AssertionError("No instances");
  }

  static List<Map<String, Object>> nodes(
      final List<String> reachable,
      final List<String> externalWinners,
      final Map<String, Map<String, Object>> nodesById,
      final Map<String, String> remappedIds,
      final Set<String> removed) {
    final List<Map<String, Object>> result = new ArrayList<>();
    appendNodes(result, reachable, true, nodesById, remappedIds, removed);
    appendNodes(result, externalWinners, false, nodesById, remappedIds, removed);
    return List.copyOf(result);
  }

  private static void appendNodes(
      final List<Map<String, Object>> result,
      final List<String> nodeIds,
      final boolean reachable,
      final Map<String, Map<String, Object>> nodesById,
      final Map<String, String> remappedIds,
      final Set<String> removed) {
    for (final String oldId : nodeIds) {
      if (!removed.contains(oldId)) {
        result.add(remapNode(nodesById.get(oldId), oldId, reachable, remappedIds));
      }
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Each node occurrence needs a separate map.
  private static Map<String, Object> remapNode(
      final Map<String, Object> original,
      final String oldId,
      final boolean reachable,
      final Map<String, String> remappedIds) {
    final Map<String, Object> copy = new LinkedHashMap<>(original);
    copy.put("id", remappedIds.get(oldId));
    copy.put("reachable", reachable);
    remapWinner(original, copy, remappedIds);
    return copy;
  }

  private static void remapWinner(
      final Map<String, Object> original,
      final Map<String, Object> copy,
      final Map<String, String> remappedIds) {
    final Object winner = original.get("conflictWinnerNodeId");
    if (winner instanceof String winnerId) {
      copy.put("conflictWinnerNodeId", remappedIds.get(winnerId));
    }
  }

  static List<Map<String, Object>> edges(
      final List<String> reachable,
      final Map<String, List<String>> children,
      final Map<String, String> remappedIds,
      final Set<String> removed) {
    final List<Map<String, Object>> result = new ArrayList<>();
    for (final String parent : reachable) {
      appendEdges(result, parent, children.getOrDefault(parent, List.of()), remappedIds, removed);
    }
    return List.copyOf(result);
  }

  private static void appendEdges(
      final List<Map<String, Object>> result,
      final String parent,
      final List<String> children,
      final Map<String, String> remappedIds,
      final Set<String> removed) {
    for (final String child : children) {
      if (!removed.contains(child) && remappedIds.containsKey(child)) {
        result.add(edge(remappedIds.get(parent), remappedIds.get(child)));
      }
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Every edge needs its own ordered value map.
  private static Map<String, Object> edge(final String parentId, final String childId) {
    final Map<String, Object> edge = new LinkedHashMap<>();
    edge.put("parentNodeId", parentId);
    edge.put("childNodeId", childId);
    return edge;
  }
}
