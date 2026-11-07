/* WHY: Binds exact safe graph occurrences to a later resolver
 * transformation. */

package io.github.spockz.elider.plugin;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

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
    if (!HexDigest.isLowercaseHex(sourceFingerprint, 64)) {
      throw new IllegalArgumentException("Graph projection source fingerprint is invalid");
    }
    if (!HexDigest.isLowercaseHex(projectedFingerprint, 64)) {
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

  /* package */ static void verifyBanPublication(
      final MavenBanPlan banPlan,
      final MavenArtifactViewBinding binding,
      final ResolverArtifactGraphProjection projection)
      throws MojoFailureException {
    final ResolverArtifactGraphSnapshot graph = binding.resolutionContext().pair().after();
    verifySourceProjection(projection, graph);
    final Set<String> removed =
        projection == null ? Set.of() : Set.copyOf(projection.removedNodeIds());
    final List<BanishedDependency> requested =
        banPlan.entries().stream().map(MavenBanPlan.Entry::dependency).toList();
    for (final Map<String, Object> node : graph.nodes()) {
      final BanishedDependency retainedBan = retainedBan(node, graph, requested, removed);
      if (retainedBan != null) {
        throw new MojoFailureException(
            "Resolver graph projection retains requested ban "
                + retainedBan.groupId()
                + ":"
                + retainedBan.artifactId());
      }
    }
  }

  private static void verifySourceProjection(
      final ResolverArtifactGraphProjection projection, final ResolverArtifactGraphSnapshot graph)
      throws MojoFailureException {
    if (projection != null
        && (!projection.sourceFingerprint().equals(graph.graphFingerprint())
            || !projection
                .projectedFingerprint()
                .equals(projectedFingerprint(graph, projection.removedNodeIds())))) {
      throw new MojoFailureException(
          "Ban graph projection changed before resolver-plan publication");
    }
  }

  private static BanishedDependency retainedBan(
      final Map<String, Object> node,
      final ResolverArtifactGraphSnapshot graph,
      final List<BanishedDependency> requested,
      final Set<String> removed)
      throws MojoFailureException {
    if (!Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))
        || Objects.equals(
            node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID), graph.rootNodeId())) {
      return null;
    }
    final EffectiveGraphDecisionIndex.Gavce identity = EffectiveGraphDecisionIndex.gavce(node);
    if (identity == null || removed.contains(graphNodeId(node))) {
      return null;
    }
    return requested.stream()
        .filter(
            ban ->
                ban.groupId().equals(identity.groupId())
                    && ban.artifactId().equals(identity.artifactId()))
        .findFirst()
        .orElse(null);
  }

  private static String graphNodeId(final Map<String, Object> node) throws MojoFailureException {
    final Object rawId = node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
    if (!(rawId instanceof String value)) {
      throw new MojoFailureException("Resolver graph node has no stable identity");
    }
    return value;
  }

  static String apply(
      final org.eclipse.aether.graph.DependencyNode root,
      final ResolverArtifactGraphProjection projection) {
    return ResolverArtifactGraphProjector.apply(root, projection);
  }
}
