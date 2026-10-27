// WHY: Builds an ordered, cycle-safe index for policy operations on detached graph snapshots.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Creates the ordered adjacency index used for conservative ancestor closure. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EffectiveGraphGraphIndex {
  private EffectiveGraphGraphIndex() {
    throw new AssertionError("No instances");
  }

  /** Creates the policy index for a detached graph snapshot. */
  static GraphIndex index(final ResolverArtifactGraphSnapshot snapshot) {
    return GraphIndex.of(snapshot);
  }

  /** One reachable node in the detached graph. */
  record Node(
      String nodeId, EffectiveGraphDecisionIndex.Gavce identity, Map<String, Object> payload) {}

  /** Ordered graph structure retaining repeated edge occurrences. */
  record GraphIndex(
      String rootNodeId,
      Map<String, Node> reachableNodes,
      Map<String, List<String>> parents,
      Map<String, List<String>> children,
      Map<EffectiveGraphDecisionIndex.Gavce, ArtifactCoordinate> coordinates,
      List<Map<String, Object>> nullChildEdges) {
    // WHY: Preserve edge order; allocate one detached entry per node and edge.
    @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.AvoidInstantiatingObjectsInLoops"})
    static GraphIndex of(final ResolverArtifactGraphSnapshot snapshot) {
      final Map<String, Node> nodes = new LinkedHashMap<>();
      final Map<EffectiveGraphDecisionIndex.Gavce, ArtifactCoordinate> coordinates =
          new LinkedHashMap<>();
      for (final Map<String, Object> payload : snapshot.nodes()) {
        if (!Boolean.TRUE.equals(payload.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))) {
          continue;
        }
        final String nodeId = (String) payload.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
        final EffectiveGraphDecisionIndex.Gavce identity =
            EffectiveGraphDecisionIndex.gavce(payload);
        nodes.put(nodeId, new Node(nodeId, identity, payload));
        if (identity != null) {
          final Object scopeValue =
              payload.get(ResolverArtifactGraphSnapshotSchema.EFFECTIVE_SCOPE);
          if (scopeValue instanceof String scope) {
            coordinates.putIfAbsent(
                identity,
                new ArtifactCoordinate(
                    identity.groupId(),
                    identity.artifactId(),
                    identity.version(),
                    identity.extension(),
                    identity.classifier(),
                    scope));
          }
        }
      }
      final Map<String, List<String>> parents = new LinkedHashMap<>();
      final Map<String, List<String>> children = new LinkedHashMap<>();
      final List<Map<String, Object>> nullEdges = new ArrayList<>();
      for (final Map<String, Object> edge : snapshot.edges()) {
        addEdge(edge, nodes, parents, children, nullEdges);
      }
      return new GraphIndex(
          snapshot.rootNodeId(),
          Collections.unmodifiableMap(nodes),
          immutableLists(parents),
          immutableLists(children),
          Collections.unmodifiableMap(coordinates),
          List.copyOf(nullEdges));
    }

    Set<String> ancestorsOf(final Set<String> seeds) {
      final Set<String> visited = new LinkedHashSet<>(seeds);
      final java.util.Queue<String> pending = new ArrayDeque<>(seeds);
      while (!pending.isEmpty()) {
        final String child = pending.remove();
        for (final String parent : parents.getOrDefault(child, List.of())) {
          if (visited.add(parent)) {
            pending.add(parent);
          }
        }
      }
      return visited;
    }

    private static void addEdge(
        final Map<String, Object> edge,
        final Map<String, Node> nodes,
        final Map<String, List<String>> parents,
        final Map<String, List<String>> children,
        final List<Map<String, Object>> nullEdges) {
      final Object parentValue = edge.get(ResolverArtifactGraphSnapshotSchema.PARENT_NODE_ID);
      final Object childValue = edge.get(ResolverArtifactGraphSnapshotSchema.CHILD_NODE_ID);
      if (!(parentValue instanceof String parent) || !nodes.containsKey(parent)) {
        return;
      }
      if (!(childValue instanceof String child)) {
        nullEdges.add(edge);
        return;
      }
      parents.computeIfAbsent(child, ignored -> new ArrayList<>()).add(parent);
      children.computeIfAbsent(parent, ignored -> new ArrayList<>()).add(child);
    }

    // WHY: Adjacency order follows the captured edge order for deterministic closure.
    @SuppressWarnings("PMD.UseConcurrentHashMap")
    private static Map<String, List<String>> immutableLists(
        final Map<String, List<String>> values) {
      final Map<String, List<String>> result = new LinkedHashMap<>();
      values.forEach((key, value) -> result.put(key, List.copyOf(value)));
      return Collections.unmodifiableMap(result);
    }
  }
}
