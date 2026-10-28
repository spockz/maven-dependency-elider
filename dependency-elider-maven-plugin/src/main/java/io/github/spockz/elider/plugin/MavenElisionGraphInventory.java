/* WHY: Compares resolver graph identities with Maven's effective artifact inventory. */

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
      final List<MavenElisionService.ArtifactSnapshot> inventory, final ElisionDecision decision) {
    final Set<ArtifactCoordinate> expected = new HashSet<>(decision.retainedArtifacts());
    expected.addAll(decision.elidedArtifacts());
    final Set<ArtifactCoordinate> actual = new HashSet<>();
    inventory.forEach(snapshot -> actual.add(snapshot.coordinate()));
    return actual.equals(expected) && actual.size() == inventory.size();
  }

  static boolean matchesGraph(
      final ResolverArtifactGraphSnapshot graph,
      final List<MavenElisionService.ArtifactSnapshot> inventory) {
    final Set<String> expected = new HashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : inventory) {
      final String extension = ResolvedArtifactInventoryFingerprint.resolverExtension(snapshot);
      if (!snapshot.coordinate().type().equals(extension)) {
        return false;
      }
      expected.add(inventoryKey(snapshot.coordinate(), extension));
    }
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
