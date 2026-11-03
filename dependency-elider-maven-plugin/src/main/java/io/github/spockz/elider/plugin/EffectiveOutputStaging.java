/* WHY: Keeps prepared archives and cleanup ownership together until a
 * complete generation is ready to install. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.JarTrimCache.CacheEntry;
import io.github.spockz.elider.plugin.ParallelTrimExecutor.PreparedOutputCleanup;
import io.github.spockz.elider.plugin.ServiceProviderTrimInventory.ServiceProviderInventory;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.PreparedEffectiveOutputs;
import io.github.spockz.elider.plugin.TrimOutputCoordinator.PendingOutput;
import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Owns prepared archives until generation publication or safe cleanup. */
final class EffectiveOutputStaging implements AutoCloseable {
  /** Owns preparation and publication of staged archive bytes. */
  private final ArchiveSanitizer sanitizer = new ArchiveSanitizer();

  /** Tracks files whose cleanup must wait for any detached workers. */
  private final PreparedOutputCleanup preparedOutputCleanup = new PreparedOutputCleanup(sanitizer);

  /** Keeps this batch isolated until the complete generation is published. */
  private final Path stagedGeneration;

  /* package */ EffectiveOutputStaging(final Path stagedGeneration, final Path stagedManifest) {
    this.stagedGeneration = stagedGeneration;
    if (stagedManifest != null) {
      preparedOutputCleanup.addCleanupAction(() -> Files.deleteIfExists(stagedManifest));
    }
    preparedOutputCleanup.addCleanupAction(
        () -> TrimGenerationPublisher.deleteTree(stagedGeneration));
  }

  /* package */ PreparedEffectiveOutputs prepareOutputs(
      final List<TrimCandidate> work,
      final Map<Path, ArtifactDigests> inputDigests,
      final EffectiveOutputPlan outputPlan,
      final int trimWorkers)
      throws IOException {
    final Map<TrimCandidate, CacheEntry> entries = TrimCollections.lookupMap();
    final List<ArtifactTrimRecord> records = new ArrayList<>();
    final List<TrimCandidate> toSanitize = new ArrayList<>();
    for (final TrimCandidate candidate : work) {
      final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
      if (analysis == null) {
        continue;
      }
      if (!candidate.requiresOutput()) {
        entries.put(candidate, JarTrimCache.cacheEntry(candidate, null, inputDigests));
        continue;
      }
      toSanitize.add(candidate);
    }
    final ServiceProviderInventory providerInventory =
        toSanitize.stream().anyMatch(candidate -> candidate.archive().multiRelease())
            ? ServiceProviderTrimInventory.serviceProviderInventory(outputPlan, work)
            : new ServiceProviderInventory(Set.of(), Set.of());
    final List<PendingOutput> prepared =
        ParallelTrimExecutor.mapParallel(
            toSanitize,
            trimWorkers,
            candidate -> {
              final Path stagedOutput = stagedGeneration.resolve(candidate.output().getFileName());
              final ArchiveSanitizer.PreparedOutput staged;
              if (candidate.archive().multiRelease()) {
                final Set<String> removedProviders =
                    ServiceProviderTrimInventory.removedServiceProviders(
                        candidate,
                        new TrimScanInputs(
                            outputPlan.prepared().index(),
                            outputPlan.prepared().dynamicRootInputs().scansByPath()),
                        providerInventory);
                final MultiReleaseArchivePlan plan =
                    MultiReleaseArchivePlan.create(
                        candidate.archive().snapshot().filePath(),
                        outputPlan.analysis().targetRelease(),
                        candidate.analysis().retainedClasses(),
                        removedProviders);
                staged =
                    sanitizer.prepareMultiRelease(
                        candidate.archive().snapshot().filePath(),
                        stagedOutput,
                        candidate.archive().snapshot().coordinate(),
                        candidate.analysis(),
                        plan,
                        TrimInputDigests.requiredInputDigest(
                                inputDigests, candidate.archive().snapshot().filePath())
                            .sha256());
              } else if (MrjarStrategy.parse(outputPlan.mrjarStrategy())
                      == MrjarStrategy.CLASSPATH_ONLY
                  && MultiReleaseLibraryProjection.hasRootModuleDescriptor(
                      candidate.archive().snapshot().filePath())) {
                staged =
                    sanitizer.prepareClasspathOnly(
                        candidate.archive().snapshot().filePath(),
                        stagedOutput,
                        candidate.archive().snapshot().coordinate(),
                        candidate.analysis(),
                        TrimInputDigests.requiredInputDigest(
                            inputDigests, candidate.archive().snapshot().filePath()));
              } else {
                staged =
                    sanitizer.prepareWithProvenance(
                        candidate.archive().snapshot().filePath(),
                        stagedOutput,
                        candidate.archive().snapshot().coordinate(),
                        candidate.analysis(),
                        TrimInputDigests.requiredInputDigest(
                            inputDigests, candidate.archive().snapshot().filePath()));
              }
              return preparedOutputCleanup.track(new PendingOutput(candidate, staged));
            },
            preparedOutputCleanup);
    final List<ArtifactTrimRecord> stagedRecords =
        TrimOutputCoordinator.publishOutputs(
            prepared.stream().map(PendingOutput::prepared).toList(), sanitizer::publish);
    for (int index = 0; index < prepared.size(); index++) {
      final PendingOutput pending = prepared.get(index);
      final ArtifactTrimRecord staged = stagedRecords.get(index);
      final ArtifactTrimRecord record = publishedRecord(pending, staged);
      records.add(record);
      entries.put(
          pending.candidate(), JarTrimCache.cacheEntry(pending.candidate(), record, inputDigests));
    }
    return new PreparedEffectiveOutputs(Map.copyOf(entries), List.copyOf(records));
  }

  @Override
  public void close() throws IOException {
    preparedOutputCleanup.close();
  }

  private static ArtifactTrimRecord publishedRecord(
      final PendingOutput pending, final ArtifactTrimRecord staged) {
    return new ArtifactTrimRecord(
        staged.coordinate(),
        staged.originalPath(),
        staged.originalSha256(),
        staged.originalSha1(),
        pending.candidate().output(),
        staged.trimmedSha256(),
        staged.trimmedSha1(),
        staged.totalClasses(),
        staged.retainedClasses(),
        staged.prunedClassBytes(),
        staged.originalPhysicalEntries().orElseThrow(),
        staged.trimmedPhysicalEntries().orElseThrow(),
        staged.mrjarStatus());
  }
}
