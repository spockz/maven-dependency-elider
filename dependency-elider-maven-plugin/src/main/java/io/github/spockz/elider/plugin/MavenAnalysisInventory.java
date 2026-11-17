// WHY: Captures and revalidates one Maven inventory across the analysis preparation stages.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactViews;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;

/** Owns stable snapshots and consistency checks for the Maven artifact views. */
final class MavenAnalysisInventory {
  private MavenAnalysisInventory() {
    throw new AssertionError("No instances");
  }

  /* default */ static Snapshot capture(final MavenProject project) throws IOException {
    final List<ArtifactSnapshot> resolved =
        MavenArtifactInventory.snapshots(new ArrayList<>(project.getArtifacts()));
    MavenArtifactPathValidation.validateIdentityPaths(resolved);
    final Map<Path, String> contentDigests = new ConcurrentHashMap<>();
    final String resolvedFingerprint =
        ResolvedArtifactInventoryFingerprint.fingerprint(resolved, contentDigests);
    final Set<Artifact> directView = project.getDependencyArtifacts();
    final boolean directPresent = directView != null;
    final List<ArtifactSnapshot> direct =
        MavenArtifactInventory.snapshots(directPresent ? new ArrayList<>(directView) : List.of());
    MavenArtifactPathValidation.validateIdentityPaths(direct);
    final String directFingerprint =
        directPresent
            ? ResolvedArtifactInventoryFingerprint.fingerprint(direct, contentDigests)
            : "missing";
    return new Snapshot(
        new ArtifactViews(resolved, directPresent, direct),
        resolvedFingerprint,
        directFingerprint,
        jarCandidates(resolved));
  }

  /* default */ static Snapshot capture(final MavenAnalysisResolutionContext context)
      throws IOException {
    final List<ArtifactSnapshot> resolved = context.artifacts().resolvedSnapshots();
    return new Snapshot(
        context.artifacts(),
        context.resolvedFingerprint(),
        context.directFingerprint(),
        jarCandidates(resolved));
  }

  private static List<ArtifactFileRef> jarCandidates(final List<ArtifactSnapshot> resolved)
      throws IOException {
    final List<ArtifactFileRef> candidates = new ArrayList<>();
    for (final ArtifactSnapshot snapshot : resolved) {
      if (MavenArtifactInventory.isJarCandidate(snapshot)) {
        candidates.add(ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath()));
      }
    }
    return candidates;
  }

  /* default */ record Snapshot(
      ArtifactViews views,
      String resolvedFingerprint,
      String directFingerprint,
      List<ArtifactFileRef> candidates) {
    /* default */ Snapshot {
      candidates = List.copyOf(candidates);
    }
  }
}
