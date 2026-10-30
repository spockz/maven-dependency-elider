/* WHY: Freezes per-artifact closure evidence before output planning can
 * inspect or publish it. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.nio.file.Path;
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
    int compilerRelease,
    int runtimeRelease,
    Path javaHome,
    List<String> platformIdentities,
    List<Integer> analyzedTiers,
    Map<ArtifactCoordinate, Set<String>> upperTierClasses) {
  TrimAnalysisResult {
    candidateAnalyses = TrimRootPlanner.immutableAnalysisMap(candidateAnalyses);
    candidateRoots = TrimRootPlanner.immutableSetMap(candidateRoots);
    reachableArtifacts = java.util.Collections.unmodifiableSet(new TreeSet<>(reachableArtifacts));
    javaHome = javaHome.toAbsolutePath().normalize();
    platformIdentities = List.copyOf(platformIdentities);
    analyzedTiers = analyzedTiers.stream().distinct().sorted().toList();
    upperTierClasses = TrimRootPlanner.immutableSetMap(upperTierClasses);
  }
}
