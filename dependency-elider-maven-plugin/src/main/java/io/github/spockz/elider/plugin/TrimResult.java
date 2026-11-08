/* WHY: Carries canonical artifact ordering across analysis and publication
 * so callers observe deterministic results. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Returns canonical trim outputs and optional generation ownership. */
record TrimResult(
    List<ArtifactTrimRecord> records,
    List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
    List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
    List<ArtifactCoordinate> configuredPassThroughArtifacts,
    int cacheHits,
    long maximumCacheHitNanos,
    int analysisRuns,
    TrimExecutionEnvironment executionEnvironment,
    List<DuplicateClasses.ToleratedDuplicate> toleratedDuplicates,
    Map<ArtifactCoordinate, List<ServiceDescriptorChange>> serviceDescriptorChanges) {
  /* default */ TrimResult(
      final List<ArtifactTrimRecord> records,
      final List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
      final List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
      final List<ArtifactCoordinate> configuredPassThroughArtifacts,
      final int cacheHits,
      final long maximumCacheHitNanos,
      final int analysisRuns,
      final TrimExecutionEnvironment executionEnvironment,
      final List<DuplicateClasses.ToleratedDuplicate> toleratedDuplicates) {
    this(
        records,
        multiReleasePassthroughArtifacts,
        moduleInfoPassthroughArtifacts,
        configuredPassThroughArtifacts,
        cacheHits,
        maximumCacheHitNanos,
        analysisRuns,
        executionEnvironment,
        toleratedDuplicates,
        Map.of());
  }

  /* default */ TrimResult {
    records =
        records.stream().sorted(Comparator.comparing(ArtifactTrimRecord::coordinate)).toList();
    multiReleasePassthroughArtifacts = multiReleasePassthroughArtifacts.stream().sorted().toList();
    moduleInfoPassthroughArtifacts = moduleInfoPassthroughArtifacts.stream().sorted().toList();
    configuredPassThroughArtifacts = configuredPassThroughArtifacts.stream().sorted().toList();
    java.util.Objects.requireNonNull(executionEnvironment, "executionEnvironment");
    toleratedDuplicates = List.copyOf(toleratedDuplicates);
    serviceDescriptorChanges =
        serviceDescriptorChanges.entrySet().stream()
            .collect(
                Collectors.toUnmodifiableMap(
                    Map.Entry::getKey, entry -> entry.getValue().stream().sorted().toList()));
  }

  /** Attaches accepted duplicate classes to this result. */
  /* package */ TrimResult withToleratedDuplicates(
      final List<DuplicateClasses.ToleratedDuplicate> duplicates) {
    return new TrimResult(
        records,
        multiReleasePassthroughArtifacts,
        moduleInfoPassthroughArtifacts,
        configuredPassThroughArtifacts,
        cacheHits,
        maximumCacheHitNanos,
        analysisRuns,
        executionEnvironment,
        duplicates,
        serviceDescriptorChanges);
  }

  /* package */ TrimResult withServiceDescriptorChanges(final List<TrimCandidate> candidates) {
    final Map<ArtifactCoordinate, List<ServiceDescriptorChange>> changes =
        candidates.stream()
            .filter(candidate -> !candidate.descriptorPlan().changes().isEmpty())
            .collect(
                Collectors.toUnmodifiableMap(
                    candidate -> candidate.archive().snapshot().coordinate(),
                    candidate -> candidate.descriptorPlan().changes()));
    return new TrimResult(
        records,
        multiReleasePassthroughArtifacts,
        moduleInfoPassthroughArtifacts,
        configuredPassThroughArtifacts,
        cacheHits,
        maximumCacheHitNanos,
        analysisRuns,
        executionEnvironment,
        toleratedDuplicates,
        changes);
  }

  /* package */ static TrimResult empty(final TrimExecutionEnvironment executionEnvironment) {
    return new TrimResult(
        List.of(), List.of(), List.of(), List.of(), 0, 0L, 0, executionEnvironment, List.of());
  }
}
