/* WHY: Carries canonical artifact ordering across analysis and publication
 * so callers observe deterministic results. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.util.Comparator;
import java.util.List;

/** Returns canonical trim outputs and optional generation ownership. */
record TrimResult(
    List<ArtifactTrimRecord> records,
    List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
    List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
    List<ArtifactCoordinate> configuredPassThroughArtifacts,
    int cacheHits,
    long maximumCacheHitNanos,
    int analysisRuns,
    TrimOutputGenerationCommitHandle generationCommit) {
  /* package */ TrimResult(
      final List<ArtifactTrimRecord> records,
      final List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
      final List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
      final List<ArtifactCoordinate> configuredPassThroughArtifacts,
      final int cacheHits,
      final long maximumCacheHitNanos,
      final int analysisRuns) {
    this(
        records,
        multiReleasePassthroughArtifacts,
        moduleInfoPassthroughArtifacts,
        configuredPassThroughArtifacts,
        cacheHits,
        maximumCacheHitNanos,
        analysisRuns,
        null);
  }

  TrimResult {
    records =
        records.stream().sorted(Comparator.comparing(ArtifactTrimRecord::coordinate)).toList();
    multiReleasePassthroughArtifacts = multiReleasePassthroughArtifacts.stream().sorted().toList();
    moduleInfoPassthroughArtifacts = moduleInfoPassthroughArtifacts.stream().sorted().toList();
    configuredPassThroughArtifacts = configuredPassThroughArtifacts.stream().sorted().toList();
  }

  /* package */ static TrimResult empty() {
    return new TrimResult(List.of(), List.of(), List.of(), List.of(), 0, 0L, 0);
  }
}
