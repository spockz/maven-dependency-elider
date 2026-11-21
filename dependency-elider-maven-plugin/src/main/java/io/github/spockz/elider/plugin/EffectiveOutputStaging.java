/* WHY: Keeps prepared archives and cleanup ownership together until a
 * complete generation is ready to install. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.plugin.JarTrimCache.CacheEntry;
import io.github.spockz.elider.plugin.ParallelTrimExecutor.PreparedOutputCleanup;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.OutputCheck;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.PreparedEffectiveOutputs;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.StagedArchive;
import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
import java.io.IOException;
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
  private final Path generationDirectory;

  /* package */ record PendingOutput(
      TrimCandidate candidate, ArchiveSanitizer.PreparedOutput prepared) {}

  /* package */ EffectiveOutputStaging(final Path generationDirectory) {
    this.generationDirectory = generationDirectory;
  }

  /* package */ PreparedEffectiveOutputs prepareOutputs(
      final List<TrimCandidate> work,
      final Map<Path, ArtifactDigests> inputDigests,
      final EffectiveOutputPlan outputPlan,
      final int trimWorkers)
      throws IOException {
    return prepareOutputs(work, inputDigests, outputPlan, trimWorkers, Map.of(), null);
  }

  /* package */ PreparedEffectiveOutputs prepareOutputs(
      final List<TrimCandidate> work,
      final Map<Path, ArtifactDigests> inputDigests,
      final EffectiveOutputPlan outputPlan,
      final int trimWorkers,
      final Map<Path, MultiReleaseArchivePlan.SourceData> multiReleaseSources,
      final OutputCheck outputCheck)
      throws IOException {
    final Map<TrimCandidate, CacheEntry> entries = TrimCollections.lookupMap();
    final List<ArtifactTrimRecord> records = new ArrayList<>();
    final List<TrimCandidate> toSanitize = new ArrayList<>();
    if (work.stream().anyMatch(candidate -> !candidate.descriptorPlan().ready())) {
      ServiceProviderTrimInventory.planDescriptorOutputs(outputPlan, work);
    }
    for (final TrimCandidate candidate : work) {
      final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
      if (analysis == null) {
        continue;
      }
      if (!candidate.requiresOutput()
          && !requiresClasspathOnlyModuleRemoval(candidate, outputPlan)) {
        entries.put(candidate, JarTrimCache.cacheEntry(candidate, null, inputDigests));
        continue;
      }
      toSanitize.add(candidate);
    }
    final List<PendingOutput> prepared =
        ParallelTrimExecutor.mapParallel(
            toSanitize,
            trimWorkers,
            candidate -> {
              final Path stagedOutput =
                  generationDirectory.resolve(candidate.output().getFileName());
              final ArchiveSanitizer.PreparedOutput staged;
              final Set<String> removedProviders = candidate.descriptorPlan().removedProviders();
              if (candidate.archive().multiRelease()) {
                final MultiReleaseArchivePlan plan =
                    prepareMultiReleasePlan(
                        candidate, outputPlan, inputDigests, multiReleaseSources, removedProviders);
                staged =
                    sanitizer.prepareMultiRelease(
                        candidate.archive().snapshot().filePath(),
                        stagedOutput,
                        candidate.archive().snapshot().coordinate(),
                        candidate.analysis(),
                        plan);
              } else if (requiresClasspathOnlyModuleRemoval(candidate, outputPlan)) {
                staged =
                    sanitizer.prepareClasspathOnly(
                        candidate.archive().snapshot().filePath(),
                        stagedOutput,
                        candidate.archive().snapshot().coordinate(),
                        candidate.analysis(),
                        TrimInputDigests.requiredInputDigest(
                            inputDigests, candidate.archive().snapshot().filePath()),
                        removedProviders);
              } else {
                staged =
                    sanitizer.prepareWithProvenance(
                        candidate.archive().snapshot().filePath(),
                        stagedOutput,
                        candidate.archive().snapshot().coordinate(),
                        candidate.analysis(),
                        TrimInputDigests.requiredInputDigest(
                            inputDigests, candidate.archive().snapshot().filePath()),
                        removedProviders);
              }
              return preparedOutputCleanup.track(new PendingOutput(candidate, staged));
            },
            preparedOutputCleanup);
    if (outputCheck != null) {
      outputCheck.check(
          prepared.stream()
              .map(PendingOutput::prepared)
              .collect(
                  java.util.stream.Collectors.toUnmodifiableMap(
                      ArchiveSanitizer.PreparedOutput::coordinate,
                      output -> new StagedArchive(output.temporaryJar(), output.outputPath()))));
    }
    final List<ArtifactTrimRecord> stagedRecords = new ArrayList<>(prepared.size());
    for (final PendingOutput pending : prepared) {
      stagedRecords.add(sanitizer.publish(pending.prepared()));
    }
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

  private static MultiReleaseArchivePlan prepareMultiReleasePlan(
      final TrimCandidate candidate,
      final EffectiveOutputPlan outputPlan,
      final Map<Path, ArtifactDigests> inputDigests,
      final Map<Path, MultiReleaseArchivePlan.SourceData> multiReleaseSources,
      final Set<String> removedProviders)
      throws IOException {
    final Path normalizedSource =
        candidate.archive().snapshot().filePath().toAbsolutePath().normalize();
    final MultiReleaseArchivePlan.SourceData sharedSource =
        multiReleaseSources.get(normalizedSource);
    final MultiReleaseArchivePlan.SourceData sourceData;
    if (sharedSource != null) {
      sourceData = sharedSource;
    } else {
      MultiReleaseWorkObserver.recordSourceInspected(normalizedSource);
      sourceData =
          MultiReleaseArchivePlan.inspectSource(
              normalizedSource, inputDigests.get(normalizedSource));
    }
    return MultiReleaseArchivePlan.create(
        sourceData,
        outputPlan.analysis().targetRelease(),
        candidate.analysis().retainedClasses(),
        removedProviders);
  }

  private static boolean requiresClasspathOnlyModuleRemoval(
      final TrimCandidate candidate, final EffectiveOutputPlan outputPlan) throws IOException {
    return MrjarStrategy.parse(outputPlan.mrjarStrategy()) == MrjarStrategy.CLASSPATH_ONLY
        && MultiReleaseLibraryProjection.hasRootModuleDescriptor(
            candidate.archive().snapshot().filePath());
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
