/* WHY: Freezes closure evidence and upper-tier classes before archive output
 * planning inspects the analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TierCandidatePlanner.TierCandidate;
import io.github.spockz.elider.plugin.TierClosureAnalyzer.ClosureResult;
import io.github.spockz.elider.plugin.TierInventoryReader.Inventory;
import io.github.spockz.elider.plugin.TierRootPlanner.RootPlan;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Assembles closure and upper-tier evidence for output planning. */
final class TierAnalysisResultBuilder {
  /** Zero-target evidence is retained for candidates without target-visible roots. */
  private static final DependencyJarTrimmer.TrimAnalysis EMPTY_ANALYSIS =
      new DependencyJarTrimmer.TrimAnalysis(0, Set.of(), Set.of(), Set.of());

  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierAnalysisResultBuilder(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ TrimAnalysisResult createResult(
      final Inventory inventory,
      final RootPlan roots,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
      final ClosureResult closure)
      throws IOException {
    final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> analyses =
        mutableAnalyses(closure.targetAnalyses());
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : roots.candidateSnapshots()) {
      analyses.computeIfAbsent(snapshot.coordinate(), ignored -> EMPTY_ANALYSIS);
    }
    final Map<ArtifactCoordinate, Set<String>> upperClasses =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootMap =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    for (final Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> entry :
        candidates.entrySet()) {
      final TierCandidate candidate = entry.getValue();
      rootMap.put(entry.getKey(), candidate.roots());
      if (candidate.isMultiRelease()) {
        final Set<String> upper = classNamesAboveRelease(entry.getKey());
        upperClasses.put(entry.getKey().coordinate(), upper);
      }
    }
    return TrimRootPlanner.inMemoryResult(
        analyses,
        rootMap,
        closure.reachableArtifacts(),
        closure.analysisRuns(),
        operation.targetRelease(),
        operation.runtimeRelease(),
        inventory.tiers(),
        inventory.platformSnapshots(),
        upperClasses);
  }

  private Set<String> classNamesAboveRelease(final ElisionAnalysisModel.ArtifactSnapshot snapshot)
      throws IOException {
    return MultiReleaseClassInventory.classNamesAboveRelease(
        snapshot.filePath(), operation.targetRelease());
  }

  private static Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> mutableAnalyses(
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> source) {
    final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> result =
        LinkedHashMap.newLinkedHashMap(source.size());
    result.putAll(source);
    return result;
  }
}
