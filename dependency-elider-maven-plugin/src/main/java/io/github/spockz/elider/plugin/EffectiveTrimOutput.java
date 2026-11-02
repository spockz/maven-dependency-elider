/* WHY: Binds effective-analysis evidence to its cache and generation path
 * before any archive is published. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.plugin.TrimCandidatePlanner.CandidatePlan;
import io.github.spockz.elider.plugin.TrimFingerprint.FingerprintOptions;
import io.github.spockz.elider.plugin.TrimFingerprint.FingerprintSnapshot;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectivePublication;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Binds effective analysis to its cache and generation output path. */
final class EffectiveTrimOutput {
  private EffectiveTrimOutput() {}

  /* package */ static TrimResult trimEffectivePrepared(
      final TrimRequest request,
      final int release,
      final int runtimeRelease,
      final JdkPlatformContext platformContext,
      final EffectiveOutputPlan effectiveOutput)
      throws IOException, MojoFailureException {
    final MavenProject project = request.project();
    final TrimPassThroughPlan passThrough = TrimPassThroughPlanner.passThroughPlan(request);
    final CandidatePlan plan =
        EffectiveCandidatePlanner.effectiveCandidatePlan(
            project,
            passThrough.retainedLibraries(),
            passThrough.retained(),
            request.scanInputs().classIndex().classesByArtifact(),
            effectiveOutput);
    final List<Path> retainedInputPaths =
        TrimCandidatePlanner.fullJarInventory(request.candidates()).stream()
            .map(ElisionAnalysisModel.ArtifactSnapshot::filePath)
            .toList();
    final List<TrimCandidate> work = plan.work();
    final Path manifest = TrimPaths.cacheManifestPath(project);
    final long cacheStart = System.nanoTime();
    final FingerprintSnapshot fingerprint =
        TrimFingerprint.fingerprint(
            work,
            retainedInputPaths,
            passThrough.skippedArtifactIdentities(),
            new FingerprintOptions(
                runtimeRelease,
                release,
                MavenDependencyTrimmer.CACHE_SCHEMA_VERSION,
                TrimFingerprint.ENGINE_VERSION,
                platformContext,
                effectiveOutput.analysis().analyzedTiers(),
                EffectiveTrimCacheContext.effectiveCacheContext(request, effectiveOutput),
                request
                    .cacheProducerIdentity()
                    .map(CacheProducerIdentity::canonicalCompatibilityIdentity)));
    TrimGenerationPublisher.verifyEffectiveInputs(effectiveOutput, fingerprint);
    final List<String> platformIdentities =
        fingerprint.platformSnapshots().stream()
            .map(JdkPlatformContext.PlatformSnapshot::identity)
            .toList();
    if (!platformIdentities.equals(effectiveOutput.analysis().platformIdentities())) {
      throw new IOException("JDK platform identity changed after effective analysis");
    }
    final String completeFingerprint = fingerprint.value();
    final Path generation =
        request.cacheProducerIdentity().isPresent()
            ? TrimPaths.generationPath(project, completeFingerprint)
            : TrimPaths.ephemeralGenerationPath();
    work.forEach(candidate -> candidate.relocateOutput(generation));
    if (request.cacheProducerIdentity().isEmpty()) {
      work.forEach(candidate -> candidate.output().toFile().deleteOnExit());
    }
    TrimCandidatePlanner.assignEffectiveAnalyses(plan, effectiveOutput.analysis());
    final TrimResult cached =
        request.cacheProducerIdentity().isPresent()
            ? JarTrimCache.loadCache(
                manifest,
                completeFingerprint,
                fingerprint.inputDigests(),
                work,
                passThrough.multiReleaseCoordinates(),
                passThrough.moduleInfoCoordinates(),
                passThrough.configuredCoordinates(),
                request.cacheProducerIdentity().orElseThrow(),
                new JarTrimCache.CacheLoadContext(
                    new TrimExecutionEnvironment(
                        effectiveOutput.analysis().targetRelease(),
                        effectiveOutput.analysis().runtimeRelease()),
                    cacheStart))
            : null;
    if (cached != null) {
      TrimGenerationPublisher.verifyEffectiveInputs(effectiveOutput, fingerprint);
      return cached;
    }
    return TrimGenerationPublisher.publishEffectiveOutputs(
        new EffectivePublication(
            effectiveOutput,
            work,
            fingerprint,
            manifest,
            completeFingerprint,
            generation,
            request.cacheProducerIdentity(),
            passThrough.multiReleaseCoordinates(),
            passThrough.moduleInfoCoordinates(),
            passThrough.configuredCoordinates(),
            effectiveOutput.analysis().analysisRuns()));
  }
}
