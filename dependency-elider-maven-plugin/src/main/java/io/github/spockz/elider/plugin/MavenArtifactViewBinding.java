// WHY: Reconciles an isolated Resolver plan with exact live Maven artifact objects before the
// transactional publisher may mutate their views.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactViews;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;

/** Exact pre-analysis live views and their unique detached resolver correspondence. */
record MavenArtifactViewBinding(
    ArtifactViews liveViews,
    String resolvedFingerprint,
    String directFingerprint,
    MavenAnalysisResolutionContext resolutionContext) {
  MavenArtifactViewBinding {
    Objects.requireNonNull(liveViews, "liveViews");
    Objects.requireNonNull(resolvedFingerprint, "resolvedFingerprint");
    Objects.requireNonNull(directFingerprint, "directFingerprint");
    Objects.requireNonNull(resolutionContext, "resolutionContext");
  }

  /* package */ static LiveSnapshot capture(final MavenProject project) throws IOException {
    final List<ArtifactSnapshot> resolved =
        MavenArtifactInventory.snapshots(new ArrayList<>(project.getArtifacts()));
    final Set<Artifact> directView = project.getDependencyArtifacts();
    final boolean directPresent = directView != null;
    final List<ArtifactSnapshot> direct =
        MavenArtifactInventory.snapshots(directPresent ? new ArrayList<>(directView) : List.of());
    MavenArtifactPathValidation.validateIdentityPaths(resolved);
    MavenArtifactPathValidation.validateIdentityPaths(direct);
    MavenArtifactPathValidation.validateDirectPaths(resolved, direct);
    return new LiveSnapshot(
        new ArtifactViews(resolved, directPresent, direct),
        ResolvedArtifactInventoryFingerprint.fingerprint(resolved),
        directPresent ? ResolvedArtifactInventoryFingerprint.fingerprint(direct) : "missing");
  }

  /* package */ static MavenArtifactViewBinding bind(
      final LiveSnapshot live, final MavenAnalysisResolutionContext context) throws IOException {
    if (live.liveViews().directArtifactsPresent() != context.artifacts().directArtifactsPresent()) {
      throw new IOException("Detached Resolver changed Maven direct-view presence");
    }
    requireUniqueCompleteCorrespondence(
        "resolved", live.liveViews().resolvedSnapshots(), context.artifacts().resolvedSnapshots());
    if (live.liveViews().directArtifactsPresent()) {
      requireUniqueCompleteCorrespondence(
          "direct", live.liveViews().directSnapshots(), context.artifacts().directSnapshots());
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

  /* package */ void verifyFresh(final MavenProject project) throws IOException {
    verifyOriginalInputsFresh();
    final List<Artifact> resolved = new ArrayList<>(project.getArtifacts());
    MavenArtifactViewValidation.validateCurrentView(
        "resolved", resolved, liveViews.resolvedSnapshots());
    ResolvedArtifactInventoryFingerprint.verifyFingerprint(
        liveViews.resolvedSnapshots(), resolvedFingerprint);
    final Set<Artifact> directView = project.getDependencyArtifacts();
    final boolean directPresent = directView != null;
    if (directPresent != liveViews.directArtifactsPresent()) {
      throw new IOException("Maven direct artifact view presence changed after ban planning");
    }
    final List<Artifact> direct = directView == null ? List.of() : new ArrayList<>(directView);
    MavenArtifactViewValidation.validateCurrentView("direct", direct, liveViews.directSnapshots());
    if (liveViews.directArtifactsPresent()) {
      ResolvedArtifactInventoryFingerprint.verifyFingerprint(
          liveViews.directSnapshots(), directFingerprint);
    }
  }

  /* package */ void verifyOriginalInputsFresh() throws IOException {
    resolutionContext.verify();
    ResolvedArtifactInventoryFingerprint.verifyFingerprint(
        liveViews.resolvedSnapshots(), resolvedFingerprint);
    if (liveViews.directArtifactsPresent()) {
      ResolvedArtifactInventoryFingerprint.verifyFingerprint(
          liveViews.directSnapshots(), directFingerprint);
    }
  }

  private static void requireUniqueCompleteCorrespondence(
      final String viewName,
      final List<ArtifactSnapshot> live,
      final List<ArtifactSnapshot> detached)
      throws IOException {
    if (live.size() != detached.size()) {
      throw new IOException("Detached Resolver " + viewName + " view is incomplete");
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
            "Detached Resolver "
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

  private record ArtifactKey(
      ArtifactCoordinate coordinate, String extension, Path path, String sha256) {
    private static ArtifactKey of(final ArtifactSnapshot snapshot) throws IOException {
      final String extension = ResolvedArtifactInventoryFingerprint.resolverExtension(snapshot);
      if (extension == null || extension.isBlank()) {
        throw new IOException(
            "Cannot bind Maven artifact type to Resolver extension: " + snapshot.coordinate());
      }
      final Path path = snapshot.filePath();
      final String sha256 = path == null ? "missing" : ArtifactDigests.read(path).sha256();
      return new ArtifactKey(snapshot.coordinate(), extension, path, sha256);
    }
  }
}
