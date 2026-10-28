/* WHY: Selects deterministic shortest root paths while preserving captured edge order. */

package io.github.spockz.elider.plugin;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Computes first shortest paths for all reachable node occurrences. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal graph report helper.
final class MediatedGraphShortestPaths {
  private MediatedGraphShortestPaths() {
    throw new AssertionError("No instances");
  }

  static Map<String, List<String>> from(final ResolverArtifactGraphSnapshot snapshot) {
    final String root = snapshot.rootNodeId();
    if (root == null) {
      return Map.of();
    }
    final Map<String, List<String>> childrenByParent = childrenByParent(snapshot);
    final Map<String, String> parents = breadthFirstParents(root, childrenByParent);
    return pathsFromParents(root, parents);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Resolver edge order defines stable tie selection.
  private static Map<String, List<String>> childrenByParent(
      final ResolverArtifactGraphSnapshot snapshot) {
    final Map<String, List<String>> childrenByParent = new LinkedHashMap<>();
    for (final Map<String, Object> edge : snapshot.edges()) {
      if (edge.get(ResolverArtifactGraphSnapshotSchema.CHILD_NODE_ID) instanceof String child) {
        final String parent = (String) edge.get(ResolverArtifactGraphSnapshotSchema.PARENT_NODE_ID);
        addChild(childrenByParent, parent, child);
      }
    }
    return childrenByParent;
  }

  private static void addChild(
      final Map<String, List<String>> childrenByParent, final String parent, final String child) {
    List<String> children = childrenByParent.get(parent);
    if (children == null) {
      children = new ArrayList<>();
      childrenByParent.put(parent, children);
    }
    children.add(child);
  }

  @SuppressWarnings(
      "PMD.UseConcurrentHashMap") // BFS encounter order fixes deterministic parent choice.
  private static Map<String, String> breadthFirstParents(
      final String root, final Map<String, List<String>> childrenByParent) {
    final Map<String, String> parents = new LinkedHashMap<>();
    final Set<String> visited = new LinkedHashSet<>();
    final Deque<String> pending = new ArrayDeque<>();
    visited.add(root);
    pending.add(root);
    while (!pending.isEmpty()) {
      final String parent = pending.removeFirst();
      for (final String child : childrenByParent.getOrDefault(parent, List.of())) {
        if (visited.add(child)) {
          parents.put(child, parent);
          pending.addLast(child);
        }
      }
    }
    return parents;
  }

  @SuppressWarnings(
      "PMD.UseConcurrentHashMap") // Parent insertion order follows BFS discovery order.
  private static Map<String, List<String>> pathsFromParents(
      final String root, final Map<String, String> parents) {
    final Map<String, List<String>> paths = new LinkedHashMap<>();
    paths.put(root, List.of(root));
    parents.forEach(
        (child, parent) -> {
          final List<String> path = new ArrayList<>(paths.get(parent));
          path.add(child);
          paths.put(child, List.copyOf(path));
        });
    return paths;
  }
}
