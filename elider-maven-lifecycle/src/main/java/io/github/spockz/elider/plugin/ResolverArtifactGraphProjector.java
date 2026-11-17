// WHY: Applies a verified projection and restores source lists on mismatch.

package io.github.spockz.elider.plugin;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import org.eclipse.aether.graph.DependencyNode;

/** Mutates a resolver graph after its detached source fingerprint is verified. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // This Aether adapter is package-internal.
final class ResolverArtifactGraphProjector {
  private ResolverArtifactGraphProjector() {
    throw new AssertionError("No instances");
  }

  static String apply(final DependencyNode root, final ResolverArtifactGraphProjection projection) {
    if (root == null) {
      throw new IllegalArgumentException("Cannot project a null dependency graph");
    }
    final LiveGraph graph = LiveGraph.capture(root);
    final Set<String> removed = Set.copyOf(projection.removedNodeIds());
    graph.validateRemovedNodes(removed);
    final Map<DependencyNode, List<DependencyNode>> originalChildren = graph.originalChildren();
    return applyAndVerify(root, projection, graph, originalChildren, removed);
  }

  @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.ExceptionAsFlowControl"})
  // Any failure after mutation must restore original child-list references.
  private static String applyAndVerify(
      final DependencyNode root,
      final ResolverArtifactGraphProjection projection,
      final LiveGraph graph,
      final Map<DependencyNode, List<DependencyNode>> originalChildren,
      final Set<String> removed) {
    try {
      graph.removeChildren(removed);
      final String result = fingerprint(root);
      if (projection.projectedFingerprint().equals(result)) {
        return result;
      }
      throw new IllegalArgumentException("Projected graph does not match its expected fingerprint");
    } catch (final RuntimeException failure) {
      graph.restoreChildren(originalChildren);
      throw new IllegalArgumentException(
          "Graph projection failed after restoring its source graph", failure);
    }
  }

  private static String fingerprint(final DependencyNode root) {
    return ResolverArtifactGraphSnapshot.capture(root, "projection-check", false, null, 0L, 0L)
        .graphFingerprint();
  }

  /** Captured request graph with stable node-identity mappings. */
  private static final class LiveGraph {
    /** Nodes keyed by the canonical encounter IDs used in the detached capture. */
    private final Map<String, DependencyNode> nodes;

    /** Resolver node identity maps to its canonical encounter ID. */
    private final Map<DependencyNode, String> ids;

    private LiveGraph(
        final Map<String, DependencyNode> nodes, final Map<DependencyNode, String> ids) {
      this.nodes = nodes;
      this.ids = ids;
    }

    @SuppressWarnings("PMD.UseConcurrentHashMap") // Traversal order and node identity are semantic.
    private static LiveGraph capture(final DependencyNode root) {
      final Map<String, DependencyNode> nodes = new LinkedHashMap<>();
      final Map<DependencyNode, String> ids = new IdentityHashMap<>();
      final Set<DependencyNode> visited = Collections.newSetFromMap(new IdentityHashMap<>());
      final Queue<DependencyNode> queue = new ArrayDeque<>();
      visited.add(root);
      ids.put(root, "n0");
      nodes.put("n0", root);
      queue.add(root);
      drain(queue, nodes, ids, visited);
      return new LiveGraph(nodes, ids);
    }

    private static void drain(
        final Queue<DependencyNode> queue,
        final Map<String, DependencyNode> nodes,
        final Map<DependencyNode, String> ids,
        final Set<DependencyNode> visited) {
      while (!queue.isEmpty()) {
        final DependencyNode parent = queue.remove();
        for (final DependencyNode child : validatedChildren(parent)) {
          addChild(child, queue, nodes, ids, visited);
        }
      }
    }

    private static List<DependencyNode> validatedChildren(final DependencyNode parent) {
      final List<DependencyNode> children = parent.getChildren();
      if (children == null) {
        throw new IllegalArgumentException("Live dependency graph has incomplete children");
      }
      for (final DependencyNode child : children) {
        if (child == null) {
          throw new IllegalArgumentException("Live dependency graph has a null child edge");
        }
      }
      return children;
    }

    private static void addChild(
        final DependencyNode child,
        final Queue<DependencyNode> queue,
        final Map<String, DependencyNode> nodes,
        final Map<DependencyNode, String> ids,
        final Set<DependencyNode> visited) {
      if (!ids.containsKey(child)) {
        final String nodeId = "n" + ids.size();
        ids.put(child, nodeId);
        nodes.put(nodeId, child);
      }
      if (visited.add(child)) {
        queue.add(child);
      }
    }

    private void validateRemovedNodes(final Set<String> removed) {
      if (!nodes.keySet().containsAll(removed) || removed.contains("n0")) {
        throw new IllegalArgumentException("Projection node IDs do not match the live graph");
      }
    }

    @SuppressWarnings("PMD.UseConcurrentHashMap") // Child-list snapshots must key by node identity.
    private Map<DependencyNode, List<DependencyNode>> originalChildren() {
      // Identity keys preserve each live resolver node independently.
      final Map<DependencyNode, List<DependencyNode>> result = new IdentityHashMap<>();
      nodes.values().forEach(node -> result.put(node, node.getChildren()));
      return result;
    }

    private void removeChildren(final Set<String> removed) {
      for (final DependencyNode parent : nodes.values()) {
        if (!removed.contains(ids.get(parent))) {
          retainChildren(parent, removed);
        }
      }
    }

    private void retainChildren(final DependencyNode parent, final Set<String> removed) {
      final List<DependencyNode> children = parent.getChildren();
      final List<DependencyNode> retained = retainedChildren(children, removed);
      if (retained.size() != children.size()) {
        parent.setChildren(retained);
      }
    }

    private List<DependencyNode> retainedChildren(
        final List<DependencyNode> children, final Set<String> removed) {
      final List<DependencyNode> retained = new ArrayList<>(children.size());
      for (final DependencyNode child : children) {
        if (!removed.contains(ids.get(child))) {
          retained.add(child);
        }
      }
      return retained;
    }

    private void restoreChildren(final Map<DependencyNode, List<DependencyNode>> originalChildren) {
      originalChildren.forEach(DependencyNode::setChildren);
    }
  }
}
