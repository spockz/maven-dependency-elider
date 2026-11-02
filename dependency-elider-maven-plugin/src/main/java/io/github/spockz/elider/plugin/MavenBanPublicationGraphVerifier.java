// WHY: Validates the final Resolver graph projection against the normalized ban plan.

package io.github.spockz.elider.plugin;

import java.util.List;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

/** Checks that every reachable requested ban is absent from the projected graph. */
final class MavenBanPublicationGraphVerifier {
  private MavenBanPublicationGraphVerifier() {}

  /* package */ static void verify(
      final MavenBanPlan banPlan,
      final MavenArtifactViewBinding binding,
      final ResolverArtifactGraphProjection projection)
      throws MojoFailureException {
    final ResolverArtifactGraphSnapshot graph = binding.resolutionContext().pair().after();
    verifyProjectionFingerprint(graph, projection);
    final Set<String> removed = removedNodeIds(projection);
    final List<BanishedDependency> requested =
        banPlan.entries().stream().map(MavenBanPlan.Entry::dependency).toList();
    for (final java.util.Map<String, Object> node : graph.nodes()) {
      if (isNonRootReachable(node, graph)
          && isRequestedBan(EffectiveGraphDecisionIndex.gavce(node), requested)
          && !removed.contains(nodeId(node))) {
        final EffectiveGraphDecisionIndex.Gavce identity = EffectiveGraphDecisionIndex.gavce(node);
        throw new MojoFailureException(
            "Resolver graph projection retains requested ban "
                + identity.groupId()
                + ":"
                + identity.artifactId());
      }
    }
  }

  private static void verifyProjectionFingerprint(
      final ResolverArtifactGraphSnapshot graph, final ResolverArtifactGraphProjection projection)
      throws MojoFailureException {
    if (projection == null) {
      return;
    }
    final boolean fingerprintMatches =
        projection.sourceFingerprint().equals(graph.graphFingerprint())
            && projection
                .projectedFingerprint()
                .equals(
                    ResolverArtifactGraphProjection.projectedFingerprint(
                        graph, projection.removedNodeIds()));
    if (!fingerprintMatches) {
      throw new MojoFailureException(
          "Ban graph projection changed before resolver-plan publication");
    }
  }

  private static Set<String> removedNodeIds(final ResolverArtifactGraphProjection projection) {
    return projection == null ? Set.of() : Set.copyOf(projection.removedNodeIds());
  }

  private static boolean isNonRootReachable(
      final java.util.Map<String, Object> node, final ResolverArtifactGraphSnapshot graph) {
    return Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))
        && !java.util.Objects.equals(
            node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID), graph.rootNodeId());
  }

  private static boolean isRequestedBan(
      final EffectiveGraphDecisionIndex.Gavce identity, final List<BanishedDependency> requested) {
    return identity != null
        && requested.stream()
            .anyMatch(
                ban ->
                    ban.groupId().equals(identity.groupId())
                        && ban.artifactId().equals(identity.artifactId()));
  }

  private static String nodeId(final java.util.Map<String, Object> node)
      throws MojoFailureException {
    final Object rawId = node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
    if (!(rawId instanceof String value)) {
      throw new MojoFailureException("Resolver graph node has no stable identity");
    }
    return value;
  }
}
