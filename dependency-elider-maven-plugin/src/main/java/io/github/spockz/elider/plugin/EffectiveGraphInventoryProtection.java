// WHY: Keeps unknown child inventories from being mistaken for complete graph leaves.

package io.github.spockz.elider.plugin;

import java.util.Map;

/** Protects raw removals when captured child relationships are incomplete. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EffectiveGraphInventoryProtection {
  private EffectiveGraphInventoryProtection() {
    throw new AssertionError("No instances");
  }

  static void protectUnknownChildren(
      final ResolverArtifactGraphCapturePair pair,
      final EffectiveGraphGraphIndex.GraphIndex graph,
      final EffectiveGraphDecisionIndex.DecisionIndex decisions,
      final Map<EffectiveGraphDecisionIndex.Gavce, String> reasons) {
    protectNullEdges(graph, decisions, reasons);
    for (final EffectiveGraphGraphIndex.Node node : graph.reachableNodes().values()) {
      if (!Boolean.TRUE.equals(
              node.payload().get(ResolverArtifactGraphSnapshotSchema.CHILDREN_PRESENT))
          && decisions.isElided(node.identity())) {
        reasons.put(node.identity(), "candidate node has incomplete child inventory");
      }
    }
    final boolean preGraphIncomplete = hasIncompleteChildren(pair.before());
    final boolean postGraphIncomplete = hasIncompleteChildren(pair.after());
    if (preGraphIncomplete || postGraphIncomplete) {
      final String reason =
          preGraphIncomplete
              ? "pre-mediation graph has incomplete conflict visibility"
              : "post-mediation graph has incomplete child inventory";
      decisions.elided().forEach(identity -> reasons.putIfAbsent(identity, reason));
    }
  }

  private static void protectNullEdges(
      final EffectiveGraphGraphIndex.GraphIndex graph,
      final EffectiveGraphDecisionIndex.DecisionIndex decisions,
      final Map<EffectiveGraphDecisionIndex.Gavce, String> reasons) {
    for (final Map<String, Object> edge : graph.nullChildEdges()) {
      final EffectiveGraphGraphIndex.Node parent =
          graph.reachableNodes().get(edge.get(ResolverArtifactGraphSnapshotSchema.PARENT_NODE_ID));
      if (parent != null && decisions.isElided(parent.identity())) {
        reasons.put(parent.identity(), "graph contains an unknown null child edge");
      }
    }
  }

  private static boolean hasIncompleteChildren(final ResolverArtifactGraphSnapshot snapshot) {
    return snapshot.nodes().stream()
        .anyMatch(
            node ->
                Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))
                    && !Boolean.TRUE.equals(
                        node.get(ResolverArtifactGraphSnapshotSchema.CHILDREN_PRESENT)));
  }
}
