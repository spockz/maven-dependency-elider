/* WHY: Owns prepared direct archives until the complete batch is ready for
 * ordered publication and cleanup. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.DirectTrimPreparation.PreparedDirectTrim;
import io.github.spockz.elider.plugin.JarTrimCache.CacheEntry;
import io.github.spockz.elider.plugin.ParallelTrimExecutor.PreparedOutputCleanup;
import io.github.spockz.elider.plugin.TrimFingerprint.FingerprintSnapshot;
import io.github.spockz.elider.plugin.TrimOutputCoordinator.PendingOutput;
import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Stages and publishes a completed direct trim batch. */
final class DirectArchiveStaging {
  private DirectArchiveStaging() {}

  /* package */ record PublishedArchives(
      List<ArtifactTrimRecord> records, Map<TrimCandidate, CacheEntry> entries) {}

  /* package */ static PublishedArchives publish(final PreparedDirectTrim plan) throws IOException {
    final List<TrimCandidate> work = plan.candidatePlan().work();
    final TrimRequest request = plan.request();
    final FingerprintSnapshot fingerprintSnapshot = plan.fingerprint();
    final List<ArtifactTrimRecord> records = new ArrayList<>();
    final ArchiveSanitizer sanitizer = new ArchiveSanitizer();
    final Map<TrimCandidate, CacheEntry> entriesByCandidate = TrimCollections.lookupMap();
    try (PreparedOutputCleanup preparedOutputCleanup = new PreparedOutputCleanup(sanitizer)) {
      final List<TrimCandidate> toSanitize = new ArrayList<>();
      for (final TrimCandidate candidate : work) {
        final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
        if (analysis == null) {
          continue;
        }
        if (analysis.retainedClasses().size() == analysis.totalClasses()) {
          entriesByCandidate.put(
              candidate,
              JarTrimCache.cacheEntry(candidate, null, fingerprintSnapshot.inputDigests()));
          continue;
        }
        toSanitize.add(candidate);
      }
      final List<PendingOutput> prepared =
          ParallelTrimExecutor.mapParallel(
              toSanitize,
              request.policy().trimWorkers(),
              candidate -> {
                final boolean isClasspathOnlyModule =
                    MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY.equals(request.policy().mrjarStrategy())
                        && MultiReleaseLibraryProjection.hasRootModuleDescriptor(
                            candidate.archive().snapshot().filePath());
                final ArchiveSanitizer.PreparedOutput staged =
                    isClasspathOnlyModule
                        ? sanitizer.prepareClasspathOnly(
                            candidate.archive().snapshot().filePath(),
                            candidate.output(),
                            candidate.archive().snapshot().coordinate(),
                            candidate.analysis(),
                            TrimInputDigests.requiredInputDigest(
                                fingerprintSnapshot.inputDigests(),
                                candidate.archive().snapshot().filePath()))
                        : sanitizer.prepareWithProvenance(
                            candidate.archive().snapshot().filePath(),
                            candidate.output(),
                            candidate.archive().snapshot().coordinate(),
                            candidate.analysis(),
                            TrimInputDigests.requiredInputDigest(
                                fingerprintSnapshot.inputDigests(),
                                candidate.archive().snapshot().filePath()));
                return preparedOutputCleanup.track(new PendingOutput(candidate, staged));
              },
              preparedOutputCleanup);
      NativeImageConsumedInput.verifyAll(request.scanInputs().consumedInputs());
      final List<ArtifactTrimRecord> publishedRecords =
          TrimOutputCoordinator.publishOutputs(
              prepared.stream().map(PendingOutput::prepared).toList(), sanitizer::publish);
      for (int index = 0; index < prepared.size(); index++) {
        final PendingOutput pending = prepared.get(index);
        final ArtifactTrimRecord record = publishedRecords.get(index);
        records.add(record);
        entriesByCandidate.put(
            pending.candidate(),
            JarTrimCache.cacheEntry(
                pending.candidate(), record, fingerprintSnapshot.inputDigests()));
      }
    }
    return new PublishedArchives(records, entriesByCandidate);
  }
}
