/* WHY: Propagates sibling references until single-release candidate roots
 * reach a fixed point. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.SingleReleaseRootPlanner.SingleReleaseRootPlan;
import io.github.spockz.elider.plugin.SingleReleaseTrimInventory.SingleReleaseInventory;
import io.github.spockz.elider.plugin.SingleReleaseTrimInventory.SingleReleaseLayout;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Computes single-release candidate closure to a fixed point. */
final class SingleReleaseClosureAnalyzer {
  private SingleReleaseClosureAnalyzer() {}

  /* package */ record SingleReleaseClosure(
      Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> analyses,
      Set<ArtifactCoordinate> reachableArtifacts,
      int analysisRuns) {}

  /* package */ static SingleReleaseClosure analyzeSingleReleaseClosure(
      final SingleReleaseInventory inventory,
      final SingleReleaseLayout layout,
      final SingleReleaseRootPlan roots,
      final int trimWorkers)
      throws IOException {
    final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> finalAnalyses =
        TrimCollections.orderedMap();
    final Set<ArtifactCoordinate> reachableArtifacts =
        new LinkedHashSet<>(roots.reachableArtifacts());
    int analysisRuns = 0;
    boolean rootsChanged;
    do {
      rootsChanged = false;
      final List<
              Map.Entry<
                  ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
          programEntries = List.copyOf(roots.preparedPrograms().entrySet());
      final List<DependencyJarTrimmer.TrimAnalysis> programAnalyses =
          ParallelTrimExecutor.mapParallel(
              programEntries,
              trimWorkers,
              entry -> entry.getValue().analyze(inventory.classesByArtifact().get(entry.getKey())));
      analysisRuns += programAnalyses.size();
      for (int index = 0; index < programEntries.size(); index++) {
        final Map.Entry<
                ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
            entry = programEntries.get(index);
        final DependencyJarTrimmer.TrimAnalysis analysis = programAnalyses.get(index);
        rootsChanged |=
            collectReachableClasses(
                analysis.reachableLibraryClasses(),
                inventory.ownerByClass(),
                layout.candidates(),
                roots.candidateRoots(),
                reachableArtifacts,
                layout.retainedCoordinates(),
                entry.getKey());
      }
      finalAnalyses.clear();
      final List<
              Map.Entry<
                  ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
          candidateEntries = List.copyOf(roots.preparedCandidates().entrySet());
      final List<DependencyJarTrimmer.TrimAnalysis> candidateAnalyses =
          ParallelTrimExecutor.mapParallel(
              candidateEntries,
              trimWorkers,
              entry -> entry.getValue().analyze(roots.candidateRoots().get(entry.getKey())));
      analysisRuns += candidateAnalyses.size();
      for (int index = 0; index < candidateEntries.size(); index++) {
        final ElisionAnalysisModel.ArtifactSnapshot candidate =
            candidateEntries.get(index).getKey();
        final DependencyJarTrimmer.TrimAnalysis analysis = candidateAnalyses.get(index);
        finalAnalyses.put(candidate.coordinate(), analysis);
        rootsChanged |=
            collectReachableClasses(
                analysis.reachableLibraryClasses(),
                inventory.ownerByClass(),
                layout.candidates(),
                roots.candidateRoots(),
                reachableArtifacts,
                layout.retainedCoordinates(),
                candidate);
      }
    } while (rootsChanged);
    return new SingleReleaseClosure(finalAnalyses, reachableArtifacts, analysisRuns);
  }

  /* package */ static boolean collectReachableClasses(
      final Set<String> reachable,
      final Map<String, ElisionAnalysisModel.ArtifactSnapshot> ownerByClass,
      final List<ElisionAnalysisModel.ArtifactSnapshot> candidates,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> candidateRoots,
      final Set<ArtifactCoordinate> reachableArtifacts,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final ElisionAnalysisModel.ArtifactSnapshot source) {
    boolean changed = false;
    for (final String reachableName : reachable) {
      final String name = reachableName.replace('/', '.');
      final ElisionAnalysisModel.ArtifactSnapshot owner = ownerByClass.get(name);
      if (owner == null || owner.equals(source)) {
        continue;
      }
      final ArtifactCoordinate coordinate = owner.coordinate();
      if (retainedCoordinates.contains(coordinate)) {
        if (candidates.contains(owner)) {
          changed |= candidateRoots.get(owner).add(name);
        }
      } else {
        reachableArtifacts.add(coordinate);
      }
    }
    return changed;
  }
}
