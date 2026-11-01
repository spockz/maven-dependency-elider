// WHY: Validates an isolated Resolver result and binds its graph and artifact bytes.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.List;
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
    final List<io.github.spockz.elider.model.ArtifactCoordinate> direct =
        MavenOriginalInputArtifacts.direct(graph.graph());
    if (!MavenElisionGraphInventory.matchesGraphCoordinates(
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
}
