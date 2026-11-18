/* WHY: Freezes per-artifact closure evidence before output planning can
 * inspect or publish it. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Freezes closure evidence before output planning. */
record TrimAnalysisResult(
    Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> candidateAnalyses,
    Map<ArtifactCoordinate, Set<String>> candidateRoots,
    Set<ArtifactCoordinate> reachableArtifacts,
    int analysisRuns,
    int targetRelease,
    int runtimeRelease,
    List<String> platformIdentities,
    List<Integer> analyzedTiers,
    Map<ArtifactCoordinate, Set<String>> upperTierClasses,
    Set<String> passThroughIdentities,
    Map<ArtifactCoordinate, Set<String>> liveProgramClasses) {
  TrimAnalysisResult {
    candidateAnalyses = TrimRootPlanner.immutableAnalysisMap(candidateAnalyses);
    candidateRoots = TrimRootPlanner.immutableSetMap(candidateRoots);
    reachableArtifacts = java.util.Collections.unmodifiableSet(new TreeSet<>(reachableArtifacts));
    platformIdentities = List.copyOf(platformIdentities);
    analyzedTiers = analyzedTiers.stream().distinct().sorted().toList();
    upperTierClasses = TrimRootPlanner.immutableSetMap(upperTierClasses);
    passThroughIdentities = Set.copyOf(passThroughIdentities);
    liveProgramClasses = TrimRootPlanner.immutableSetMap(liveProgramClasses);
  }

  /* package */ TrimAnalysisResult(
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> candidateAnalyses,
      final Map<ArtifactCoordinate, Set<String>> candidateRoots,
      final Set<ArtifactCoordinate> reachableArtifacts,
      final int analysisRuns,
      final int targetRelease,
      final int runtimeRelease,
      final List<String> platformIdentities,
      final List<Integer> analyzedTiers,
      final Map<ArtifactCoordinate, Set<String>> upperTierClasses) {
    this(
        candidateAnalyses,
        candidateRoots,
        reachableArtifacts,
        analysisRuns,
        targetRelease,
        runtimeRelease,
        platformIdentities,
        analyzedTiers,
        upperTierClasses,
        Set.of(),
        Map.of());
  }

  /* package */ TrimAnalysisResult withPassThroughIdentities(
      final Set<String> passThroughIdentities) {
    return new TrimAnalysisResult(
        candidateAnalyses,
        candidateRoots,
        reachableArtifacts,
        analysisRuns,
        targetRelease,
        runtimeRelease,
        platformIdentities,
        analyzedTiers,
        upperTierClasses,
        passThroughIdentities,
        liveProgramClasses);
  }

  /* package */ TrimAnalysisResult withLiveProgramClasses(
      final Map<ArtifactCoordinate, Set<String>> liveProgramClasses) {
    return new TrimAnalysisResult(
        candidateAnalyses,
        candidateRoots,
        reachableArtifacts,
        analysisRuns,
        targetRelease,
        runtimeRelease,
        platformIdentities,
        analyzedTiers,
        upperTierClasses,
        passThroughIdentities,
        liveProgramClasses);
  }
}
