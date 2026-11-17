// WHY: Validates an isolated Resolver result and binds its graph and artifact bytes.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.maven.project.DependencyResolutionResult;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class MavenOriginalInputInventory {
  private MavenOriginalInputInventory() {}

  static MavenOriginalInputAudit.Inventory create(
      final BanishedDependencyOriginalModel captured,
      final String projectKey,
      final DependencyResolutionResult result,
      final ResolverArtifactGraphCapturePair graphPair)
      throws IOException {
    final MavenOriginalInputResolution.Validated graph =
        MavenOriginalInputResolution.validate(projectKey, result, graphPair);
    final List<MavenOriginalInputAudit.AuditArtifact> resolvedArtifacts =
        MavenOriginalInputArtifacts.resolved(graph.dependencies());
    final List<ArtifactCoordinate> direct = MavenOriginalInputArtifacts.direct(graph.graph());
    if (!matchesGraphCoordinates(
        graph.graphPair().after(),
        resolvedArtifacts.stream()
            .map(MavenOriginalInputAudit.AuditArtifact::coordinate)
            .toList())) {
      throw new IOException("Original-input audit graph does not match its resolver inventory");
    }
    return new MavenOriginalInputAudit.Inventory(
        captured.project(),
        captured.sourceFingerprint(),
        graph.graphPair(),
        resolvedArtifacts,
        direct,
        null);
  }

  static boolean matchesGraphCoordinates(
      final ResolverArtifactGraphSnapshot graph, final List<ArtifactCoordinate> inventory) {
    final Set<String> expected = new HashSet<>();
    for (final ArtifactCoordinate coordinate : inventory) {
      expected.add(inventoryKey(coordinate, coordinate.type()));
    }
    return expected.size() == inventory.size() && matchesGraphKeys(graph, expected);
  }

  static boolean matchesGraphKeys(
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

  static String inventoryKey(final ArtifactCoordinate coordinate, final String extension) {
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

  static String inventoryKey(final EffectiveGraphDecisionIndex.Gavce identity, final String scope) {
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

  private static boolean isRoot(
      final ResolverArtifactGraphSnapshot graph, final Map<String, Object> node) {
    return Objects.equals(
        node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID), graph.rootNodeId());
  }
}
