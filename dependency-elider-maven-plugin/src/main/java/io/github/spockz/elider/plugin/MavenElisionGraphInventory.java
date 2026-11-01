/* WHY: Compares resolver graph identities with Maven's effective artifact
 * inventory. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Matches graph nodes to the separate Maven artifact inventory. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionGraphInventory {
  private MavenElisionGraphInventory() {
    throw new AssertionError("No instances");
  }

  static boolean matchesDecision(
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory, final ElisionDecision decision) {
    final Set<ArtifactCoordinate> expected = new HashSet<>(decision.retainedArtifacts());
    expected.addAll(decision.elidedArtifacts());
    final Set<ArtifactCoordinate> actual = new HashSet<>();
    inventory.forEach(snapshot -> actual.add(snapshot.coordinate()));
    return actual.equals(expected) && actual.size() == inventory.size();
  }

  static boolean matchesGraph(
      final ResolverArtifactGraphSnapshot graph,
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory) {
    final Set<String> expected = new HashSet<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory) {
      final String extension = ResolvedArtifactInventoryFingerprint.resolverExtension(snapshot);
      if (!snapshot.coordinate().type().equals(extension)) {
        return false;
      }
      expected.add(inventoryKey(snapshot.coordinate(), extension));
    }
    return matchesGraphKeys(graph, expected);
  }

  static boolean matchesGraphCoordinates(
      final ResolverArtifactGraphSnapshot graph, final List<ArtifactCoordinate> inventory) {
    final Set<String> expected = new HashSet<>();
    for (final ArtifactCoordinate coordinate : inventory) {
      expected.add(inventoryKey(coordinate, coordinate.type()));
    }
    return expected.size() == inventory.size() && matchesGraphKeys(graph, expected);
  }

  static boolean matchesDirectGraph(
      final ResolverArtifactGraphSnapshot graph,
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory) {
    final Set<String> expected = new HashSet<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory) {
      expected.add(inventoryKey(snapshot.coordinate(), snapshot.coordinate().type()));
    }
    if (expected.size() != inventory.size()) {
      return false;
    }
    final Map<String, Map<String, Object>> nodes = new java.util.HashMap<>();
    graph
        .nodes()
        .forEach(
            node -> {
              final Object id = node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
              if (id instanceof String nodeId) {
                nodes.put(nodeId, node);
              }
            });
    final Set<String> actual = new HashSet<>();
    for (final Map<String, Object> edge : graph.edges()) {
      if (!java.util.Objects.equals(
          graph.rootNodeId(), edge.get(ResolverArtifactGraphSnapshotSchema.PARENT_NODE_ID))) {
        continue;
      }
      final Object childId = edge.get(ResolverArtifactGraphSnapshotSchema.CHILD_NODE_ID);
      if (!(childId instanceof String nodeId)) {
        return false;
      }
      final Map<String, Object> node = nodes.get(nodeId);
      final EffectiveGraphDecisionIndex.Gavce identity =
          node == null ? null : EffectiveGraphDecisionIndex.gavce(node);
      final Object scope =
          node == null ? null : node.get(ResolverArtifactGraphSnapshotSchema.EFFECTIVE_SCOPE);
      if (identity == null || !(scope instanceof String value) || value.isBlank()) {
        return false;
      }
      actual.add(inventoryKey(identity, value));
    }
    return actual.equals(expected)
        && actual.size()
            == graph.edges().stream()
                .filter(
                    edge ->
                        java.util.Objects.equals(
                            graph.rootNodeId(),
                            edge.get(ResolverArtifactGraphSnapshotSchema.PARENT_NODE_ID)))
                .count();
  }

  private static boolean matchesGraphKeys(
      final ResolverArtifactGraphSnapshot graph, final Set<String> expected) {
    final Set<String> actual = new HashSet<>();
    for (final Map<String, Object> node : graph.nodes()) {
      if (!Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))) {
        continue;
      }
      if (isRoot(graph, node)) {
        continue;
      }
      final EffectiveGraphDecisionIndex.Gavce identity = EffectiveGraphDecisionIndex.gavce(node);
      final Object rawScope = node.get(ResolverArtifactGraphSnapshotSchema.EFFECTIVE_SCOPE);
      if (identity == null || !(rawScope instanceof String scope) || scope.isBlank()) {
        return false;
      }
      actual.add(inventoryKey(identity, scope));
    }
    return actual.equals(expected);
  }

  private static boolean isRoot(
      final ResolverArtifactGraphSnapshot graph, final Map<String, Object> node) {
    return java.util.Objects.equals(
        node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID), graph.rootNodeId());
  }

  private static String inventoryKey(final ArtifactCoordinate coordinate, final String extension) {
    return coordinate.groupId()
        + "\t"
        + coordinate.artifactId()
        + "\t"
        + coordinate.version()
        + "\t"
        + extension
        + "\t"
        + coordinate.classifier()
        + "\t"
        + coordinate.scope();
  }

  private static String inventoryKey(
      final EffectiveGraphDecisionIndex.Gavce identity, final String scope) {
    return identity.groupId()
        + "\t"
        + identity.artifactId()
        + "\t"
        + identity.version()
        + "\t"
        + identity.extension()
        + "\t"
        + identity.classifier()
        + "\t"
        + scope;
  }
}
