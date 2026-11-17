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
    final boolean preGraphIncomplete = hasIncompleteInventory(pair.before());
    final boolean postGraphIncomplete = hasIncompleteInventory(pair.after());
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

  private static boolean hasIncompleteInventory(final ResolverArtifactGraphSnapshot snapshot) {
    return hasMissingChildLists(snapshot) || hasNullChildEdges(snapshot);
  }

  private static boolean hasMissingChildLists(final ResolverArtifactGraphSnapshot snapshot) {
    return snapshot.nodes().stream()
        .anyMatch(
            node ->
                Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))
                    && !Boolean.TRUE.equals(
                        node.get(ResolverArtifactGraphSnapshotSchema.CHILDREN_PRESENT)));
  }

  private static boolean hasNullChildEdges(final ResolverArtifactGraphSnapshot snapshot) {
    return snapshot.edges().stream()
        .anyMatch(edge -> edge.get(ResolverArtifactGraphSnapshotSchema.CHILD_NODE_ID) == null);
  }
}
