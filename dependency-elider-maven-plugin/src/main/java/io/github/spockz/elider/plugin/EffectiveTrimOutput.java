/* WHY: Binds effective-analysis evidence to its cache and generation path
 * before any archive is published. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.plugin.TrimFingerprint.FingerprintOptions;
import io.github.spockz.elider.plugin.TrimFingerprint.FingerprintSnapshot;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectivePublication;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.OutputCheck;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.StagedArchive;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
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
      final EffectiveOutputPlan effectiveOutput,
      final OutputCheck outputCheck)
      throws IOException, MojoFailureException {
    final MavenProject project = request.project();
    final EffectiveCandidatePlanner.PlannedWork planned =
        EffectiveCandidatePlanner.planWork(request, effectiveOutput);
    final TrimPassThroughPlan passThrough = planned.passThrough();
    final List<Path> retainedInputPaths =
        TrimCandidatePlanner.fullJarInventory(request.candidates()).stream()
            .map(ElisionAnalysisModel.ArtifactSnapshot::filePath)
            .toList();
    final List<TrimCandidate> work = planned.work();
    final Path manifest = TrimPaths.cacheManifestPath(project);
    final long cacheStart = System.nanoTime();
    final Map<Path, ArtifactDigests> inputDigests =
        TrimInputDigests.inputDigests(retainedInputPaths, planned.multiReleaseSources());
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
                EffectiveTrimCacheContext.effectiveCacheContext(
                    request, effectiveOutput, inputDigests),
                request
                    .cacheProducerIdentity()
                    .map(CacheProducerIdentity::canonicalCompatibilityIdentity),
                request.runtimePlatforms()),
            inputDigests);
    final String completeFingerprint = fingerprint.value();
    final Path generation =
        request.cacheProducerIdentity().isPresent()
            ? TrimPaths.generationPath(project, completeFingerprint)
            : TrimPaths.ephemeralGenerationPath();
    work.forEach(candidate -> candidate.relocateOutput(generation));
    if (request.cacheProducerIdentity().isEmpty()) {
      work.forEach(candidate -> candidate.output().toFile().deleteOnExit());
    }
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
      if (outputCheck != null) {
        outputCheck.check(
            cached.records().stream()
                .collect(
                    java.util.stream.Collectors.toUnmodifiableMap(
                        ArtifactTrimRecord::coordinate,
                        record -> new StagedArchive(record.trimmedPath(), record.trimmedPath()))));
      }
      return cached.withServiceDescriptorChanges(work);
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
                effectiveOutput.analysis().analysisRuns(),
                planned.multiReleaseSources()),
            outputCheck)
        .withServiceDescriptorChanges(work);
  }
}
