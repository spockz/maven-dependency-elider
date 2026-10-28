/* WHY: Binds exact safe graph occurrences to a later resolver transformation. */

package io.github.spockz.elider.plugin;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Detached projection of one captured graph, keyed by exact node occurrences. */
@SuppressWarnings(
    "PMD.CommentDefaultAccessModifier") // These helpers are consumed only in this package.
record ResolverArtifactGraphProjection(
    String captureToken,
    String sourceFingerprint,
    String projectedFingerprint,
    List<String> removedNodeIds) {
  ResolverArtifactGraphProjection {
    if (captureToken == null || captureToken.isBlank()) {
      throw new IllegalArgumentException("Graph projection capture token must not be blank");
    }
    if (sourceFingerprint == null || !sourceFingerprint.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException("Graph projection source fingerprint is invalid");
    }
    if (projectedFingerprint == null || !projectedFingerprint.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException("Graph projection result fingerprint is invalid");
    }
    removedNodeIds = List.copyOf(removedNodeIds);
    if (removedNodeIds.isEmpty() || removedNodeIds.stream().anyMatch(String::isBlank)) {
      throw new IllegalArgumentException("Graph projection must contain removed node IDs");
    }
    if (new HashSet<>(removedNodeIds).size() != removedNodeIds.size()) {
      throw new IllegalArgumentException("Graph projection node IDs must be unique");
    }
  }

  static ResolverArtifactGraphProjection create(
      final ResolverArtifactGraphCapturePair pair,
      final Map<String, EffectiveGraphPolicy.NodeDisposition> dispositions) {
    Objects.requireNonNull(pair, "pair");
    final List<String> removed =
        pair.after().nodes().stream()
            .filter(node -> Boolean.TRUE.equals(node.get("reachable")))
            .filter(
                node ->
                    dispositions.get(node.get("id"))
                        == EffectiveGraphPolicy.NodeDisposition.SAFE_ELIDED)
            .map(node -> (String) node.get("id"))
            .toList();
    if (removed.isEmpty()) {
      return null;
    }
    final String projected = projectedFingerprint(pair.after(), removed);
    return new ResolverArtifactGraphProjection(
        pair.captureToken(), pair.after().graphFingerprint(), projected, removed);
  }

  static String projectedFingerprint(
      final ResolverArtifactGraphSnapshot source, final List<String> removedNodeIds) {
    return ResolverArtifactGraphProjectionFingerprint.calculate(source, removedNodeIds);
  }

  static String apply(
      final org.eclipse.aether.graph.DependencyNode root,
      final ResolverArtifactGraphProjection projection) {
    return ResolverArtifactGraphProjector.apply(root, projection);
  }
}
