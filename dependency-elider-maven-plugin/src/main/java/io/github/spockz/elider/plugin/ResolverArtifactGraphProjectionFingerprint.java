// WHY: Computes the canonical detached graph after occurrence removal.

package io.github.spockz.elider.plugin;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Builds a canonical graph fingerprint for an occurrence-level projection. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // The detached projection API stays internal.
final class ResolverArtifactGraphProjectionFingerprint {
  /** PMD rule for unordered maps that breaks deterministic traversal. */
  private static final String ORDERED_MAP_SUPPRESSION = "PMD.UseConcurrentHashMap";

  private ResolverArtifactGraphProjectionFingerprint() {
    throw new AssertionError("No instances");
  }

  static String calculate(
      final ResolverArtifactGraphSnapshot source, final List<String> removedNodeIds) {
    final Set<String> removed = new LinkedHashSet<>(removedNodeIds);
    final Map<String, Map<String, Object>> nodesById = indexNodes(source.nodes());
    validateRootAndRemovals(source.rootNodeId(), nodesById, removed);
    final Map<String, List<String>> children = childrenByParent(source.edges());
    final List<String> reachable = traversal(source.rootNodeId(), children, removed);
    final Map<String, String> remappedIds = remapIds(reachable);
    final List<String> externalWinners = externalWinners(reachable, nodesById, removed);
    appendExternalWinnerIds(externalWinners, remappedIds);
    final List<Map<String, Object>> nodes =
        ResolverArtifactGraphProjectionPayload.nodes(
            reachable, externalWinners, nodesById, remappedIds, removed);
    final List<Map<String, Object>> edges =
        ResolverArtifactGraphProjectionPayload.edges(reachable, children, remappedIds, removed);
    return ResolverArtifactGraphSnapshot.structuralFingerprint(
        remappedIds.get(source.rootNodeId()), nodes, edges);
  }

  @SuppressWarnings(ORDERED_MAP_SUPPRESSION) // Node encounter order defines canonical IDs.
  private static Map<String, Map<String, Object>> indexNodes(
      final List<Map<String, Object>> sourceNodes) {
    final Map<String, Map<String, Object>> result = new LinkedHashMap<>();
    sourceNodes.forEach(node -> result.put((String) node.get("id"), node));
    return result;
  }

  private static void validateRootAndRemovals(
      final String rootId,
      final Map<String, Map<String, Object>> nodesById,
      final Set<String> removed) {
    if (rootId == null || removed.contains(rootId)) {
      throw new IllegalArgumentException("Graph projection cannot remove or lack its root");
    }
    if (!nodesById.keySet().containsAll(removed)) {
      throw new IllegalArgumentException("Graph projection references an unknown node ID");
    }
  }

  @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.AvoidInstantiatingObjectsInLoops"})
  // Parent encounter order controls deterministic edge serialization.
  private static Map<String, List<String>> childrenByParent(final List<Map<String, Object>> edges) {
    final Map<String, List<String>> result = new LinkedHashMap<>();
    for (final Map<String, Object> edge : edges) {
      final Object parent = edge.get("parentNodeId");
      final Object child = edge.get("childNodeId");
      if (!(parent instanceof String parentId) || !(child instanceof String childId)) {
        throw new IllegalArgumentException("Graph projection requires complete graph edges");
      }
      result.computeIfAbsent(parentId, ignored -> new ArrayList<>()).add(childId);
    }
    return result;
  }

  private static List<String> traversal(
      final String rootId, final Map<String, List<String>> children, final Set<String> removed) {
    final List<String> result = new ArrayList<>();
    final Set<String> visited = new LinkedHashSet<>();
    final Deque<String> queue = new ArrayDeque<>();
    visited.add(rootId);
    queue.add(rootId);
    while (!queue.isEmpty()) {
      final String parent = queue.removeFirst();
      result.add(parent);
      for (final String child : children.getOrDefault(parent, List.of())) {
        if (!removed.contains(child) && visited.add(child)) {
          queue.addLast(child);
        }
      }
    }
    return result;
  }

  @SuppressWarnings(ORDERED_MAP_SUPPRESSION) // Insertion order is the node-ID contract.
  private static Map<String, String> remapIds(final List<String> reachable) {
    final Map<String, String> result = new LinkedHashMap<>();
    for (final String nodeId : reachable) {
      result.put(nodeId, "n" + result.size());
    }
    return result;
  }

  private static List<String> externalWinners(
      final List<String> reachable,
      final Map<String, Map<String, Object>> nodesById,
      final Set<String> removed) {
    final List<String> winners = new ArrayList<>();
    for (final String nodeId : reachable) {
      final Object winner = nodesById.get(nodeId).get("conflictWinnerNodeId");
      if (winner instanceof String winnerId && !reachable.contains(winnerId)) {
        if (removed.contains(winnerId) || !nodesById.containsKey(winnerId)) {
          throw new IllegalArgumentException("Graph projection has an invalid winner reference");
        }
        if (!winners.contains(winnerId)) {
          winners.add(winnerId);
        }
      }
    }
    return winners;
  }

  private static void appendExternalWinnerIds(
      final List<String> externalWinners, final Map<String, String> remappedIds) {
    for (final String id : externalWinners) {
      remappedIds.put(id, "n" + remappedIds.size());
    }
  }
}
