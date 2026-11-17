// WHY: Reconciles an isolated Resolver plan with exact live Maven artifact objects before the
// publication flow may mutate their views.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactViews;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.maven.project.MavenProject;

/** Exact pre-analysis live views and their unique detached resolver correspondence. */
record MavenArtifactViewBinding(
    ArtifactViews liveViews,
    String resolvedFingerprint,
    String directFingerprint,
    MavenAnalysisResolutionContext resolutionContext) {
  /** Prefix for detached resolver diagnostics. */
  private static final String DETACHED_RESOLVER = "Detached Resolver ";

  MavenArtifactViewBinding {
    Objects.requireNonNull(liveViews, "liveViews");
    Objects.requireNonNull(resolvedFingerprint, "resolvedFingerprint");
    Objects.requireNonNull(directFingerprint, "directFingerprint");
    Objects.requireNonNull(resolutionContext, "resolutionContext");
  }

  /* package */ static LiveSnapshot capture(final MavenProject project) throws IOException {
    final MavenAnalysisInventory.Snapshot snapshot = MavenAnalysisInventory.capture(project);
    MavenArtifactPathValidation.validateDirectPaths(
        snapshot.views().resolvedSnapshots(), snapshot.views().directSnapshots());
    return new LiveSnapshot(
        snapshot.views(), snapshot.resolvedFingerprint(), snapshot.directFingerprint());
  }

  /* package */ static MavenArtifactViewBinding bind(
      final LiveSnapshot live, final MavenAnalysisResolutionContext context) throws IOException {
    if (live.liveViews().directArtifactsPresent() != context.artifacts().directArtifactsPresent()) {
      throw new IOException(DETACHED_RESOLVER + "changed Maven direct-view presence");
    }
    requireUniqueCompleteCorrespondence(
        "resolved", live.liveViews().resolvedSnapshots(), context.artifacts().resolvedSnapshots());
    if (live.liveViews().directArtifactsPresent()) {
      requireUniqueCompleteCorrespondence(
          "direct", live.liveViews().directSnapshots(), context.artifacts().directSnapshots());
    }
    requireSameFingerprint("resolved", live.resolvedFingerprint(), context.resolvedFingerprint());
    if (live.liveViews().directArtifactsPresent()) {
      requireSameFingerprint("direct", live.directFingerprint(), context.directFingerprint());
    }
    return new MavenArtifactViewBinding(
        live.liveViews(), live.resolvedFingerprint(), live.directFingerprint(), context);
  }

  /* package */ Analysis bindAnalysis(final Analysis analysis) {
    return new Analysis(
        liveViews,
        analysis.decision(),
        analysis.effectiveDecision(),
        analysis.evidence(),
        analysis.trimResult(),
        analysis.graphProjection(),
        analysis.mediatedGraph(),
        analysis.policyIdentity(),
        analysis.traceDecision(),
        analysis.banPlan());
  }

  private static void requireSameFingerprint(
      final String viewName, final String liveFingerprint, final String detachedFingerprint)
      throws IOException {
    if (!liveFingerprint.equals(detachedFingerprint)) {
      throw new IOException(
          DETACHED_RESOLVER + viewName + " inventory does not match the live Maven view");
    }
  }

  private static void requireUniqueCompleteCorrespondence(
      final String viewName,
      final List<ArtifactSnapshot> live,
      final List<ArtifactSnapshot> detached)
      throws IOException {
    if (live.size() != detached.size()) {
      throw new IOException(DETACHED_RESOLVER + viewName + " view is incomplete");
    }
    final Set<ArtifactKey> liveKeys = keys(viewName, live);
    final Set<ArtifactKey> detachedKeys = keys(viewName, detached);
    if (!liveKeys.equals(detachedKeys)) {
      throw new IOException(
          "Detached Resolver " + viewName + " view does not uniquely match the live Maven view");
    }
  }

  private static Set<ArtifactKey> keys(
      final String viewName, final List<ArtifactSnapshot> snapshots) throws IOException {
    final Set<ArtifactKey> result = new HashSet<>();
    for (final ArtifactSnapshot snapshot : snapshots) {
      final ArtifactKey key = ArtifactKey.of(snapshot);
      if (!result.add(key)) {
        throw new IOException(
            DETACHED_RESOLVER
                + viewName
                + " view has ambiguous duplicate artifact "
                + key.coordinate());
      }
    }
    return result;
  }

  /* package */ record LiveSnapshot(
      ArtifactViews liveViews, String resolvedFingerprint, String directFingerprint) {
    LiveSnapshot {
      Objects.requireNonNull(liveViews, "liveViews");
      Objects.requireNonNull(resolvedFingerprint, "resolvedFingerprint");
      Objects.requireNonNull(directFingerprint, "directFingerprint");
    }
  }

  private record ArtifactKey(ArtifactCoordinate coordinate, String extension, Path path) {
    private static ArtifactKey of(final ArtifactSnapshot snapshot) throws IOException {
      final String extension = ResolvedArtifactInventoryFingerprint.resolverExtension(snapshot);
      if (extension == null || extension.isBlank()) {
        throw new IOException(
            "Cannot bind Maven artifact type to Resolver extension: " + snapshot.coordinate());
      }
      final Path path = snapshot.filePath();
      return new ArtifactKey(snapshot.coordinate(), extension, path);
    }
  }
}
