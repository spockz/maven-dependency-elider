/* WHY: Captures the direct work plan and its fingerprint before cache lookup
 * or class-pool analysis can publish any output. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TrimCandidatePlanner.CandidatePlan;
import io.github.spockz.elider.plugin.TrimFingerprint.FingerprintOptions;
import io.github.spockz.elider.plugin.TrimFingerprint.FingerprintSnapshot;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/** Captures candidate and cache inputs for direct output execution. */
final class DirectTrimPreparation {
  private DirectTrimPreparation() {}

  /* package */ record PreparedDirectTrim(
      TrimRequest request,
      TrimPassThroughPlan passThrough,
      CandidatePlan candidatePlan,
      Path manifest,
      long cacheStarted,
      FingerprintSnapshot fingerprint,
      int compilerRelease,
      int runtimeRelease) {}

  /* package */ static PreparedDirectTrim prepare(
      final TrimRequest request,
      final int release,
      final int runtimeRelease,
      final JdkPlatformContext platform)
      throws IOException {
    validateArchives(request);
    final TrimPassThroughPlan passThrough = TrimPassThroughPlanner.passThroughPlan(request);
    final CandidatePlan candidates =
        DirectCandidatePlanner.candidatePlan(
            request.project(),
            passThrough.retainedLibraries(),
            passThrough.retained(),
            request.scanInputs(),
            request.scanInputs().classIndex().classesByArtifact(),
            TrimRootPlanner.commonRoots(request));
    final Path manifest = TrimPaths.cacheManifestPath(request.project());
    final long started = System.nanoTime();
    final FingerprintSnapshot fingerprint =
        TrimFingerprint.fingerprint(
            candidates.work(),
            candidates.retainedInputPaths(),
            passThrough.skippedArtifactIdentities(),
            new FingerprintOptions(
                runtimeRelease,
                release,
                MavenDependencyTrimmer.CACHE_SCHEMA_VERSION,
                TrimFingerprint.ENGINE_VERSION,
                platform,
                List.of(release, runtimeRelease),
                null));
    return new PreparedDirectTrim(
        request, passThrough, candidates, manifest, started, fingerprint, release, runtimeRelease);
  }

  private static void validateArchives(final TrimRequest request) throws IOException {
    if (!request.policy().trimEnabled()
        || !MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING.equals(
            request.policy().mrjarStrategy())) {
      return;
    }
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
        TrimPassThroughPlanner.passThroughPlan(request).retained()) {
      validateArchive(snapshot);
    }
  }

  private static void validateArchive(final ElisionAnalysisModel.ArtifactSnapshot snapshot)
      throws IOException {
    if (MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath())) {
      throw new IOException(
          "Vertical-shading MRJAR output requires tier-aware effective analysis: "
              + snapshot.coordinate());
    }
  }
}
