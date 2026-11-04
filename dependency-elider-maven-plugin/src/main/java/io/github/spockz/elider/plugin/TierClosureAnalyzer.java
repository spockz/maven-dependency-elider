/* WHY: Propagates candidate and unchanged-program references across tiers
 * until no roots change. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierCandidatePlanner.TierCandidate;
import io.github.spockz.elider.plugin.TierInventoryReader.MultiReleaseCandidateInfo;
import io.github.spockz.elider.plugin.TierRootPlanner.RootPlan;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Propagates references until tier candidate roots stop changing. */
final class TierClosureAnalyzer {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierClosureAnalyzer(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ ClosureResult analyzeToFixedPoint(
      final List<TierContext> contexts,
      final RootPlan roots,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates)
      throws IOException {
    final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    int analysisRuns = 0;
    boolean changed;
    do {
      final ClosureIteration iteration =
          analyzeIteration(contexts, roots, candidates, targetAnalyses);
      changed = iteration.rootsChanged();
      analysisRuns += iteration.analysisRuns();
    } while (changed);
    return new ClosureResult(targetAnalyses, roots.reachableArtifacts(), analysisRuns);
  }

  private ClosureIteration analyzeIteration(
      final List<TierContext> contexts,
      final RootPlan roots,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses)
      throws IOException {
    boolean changed = false;
    int runs = 0;
    for (final TierContext context : contexts) {
      final ClosureIteration programs = analyzePrograms(context, candidates, roots);
      changed |= programs.rootsChanged();
      runs += programs.analysisRuns();
      final ClosureIteration candidateResults =
          analyzeCandidates(context, candidates, roots, targetAnalyses);
      changed |= candidateResults.rootsChanged();
      runs += candidateResults.analysisRuns();
    }
    return new ClosureIteration(changed, runs);
  }

  private ClosureIteration analyzePrograms(
      final TierContext context,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
      final RootPlan roots)
      throws IOException {
    boolean changed = false;
    final List<
            Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
        entries =
            context.programEntries().stream()
                .filter(
                    entry ->
                        !rootsForProgram(context, entry.getKey(), candidates.get(entry.getKey()))
                            .isEmpty())
                .toList();
    final List<DependencyJarTrimmer.TrimAnalysis> analyses =
        ParallelTrimExecutor.mapParallel(
            entries,
            operation.request().policy().trimWorkers(),
            entry ->
                entry
                    .getValue()
                    .analyze(
                        rootsForProgram(context, entry.getKey(), candidates.get(entry.getKey()))));
    for (int index = 0; index < entries.size(); index++) {
      final Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          entry = entries.get(index);
      final ElisionAnalysisModel.ArtifactSnapshot owner = entry.getKey();
      final TierCandidate candidate = candidates.get(owner);
      final DependencyJarTrimmer.TrimAnalysis analysis = analyses.get(index);
      if (candidate != null
          && candidate.isMultiRelease()
          && context.release() > operation.targetRelease()) {
        changed |= retainSameJarTargetClasses(candidate, analysis, context.classesOf(owner));
      }
      changed |=
          collectReachableClasses(
              analysis.reachableLibraryClasses(), owner, context, candidates, roots);
    }
    return new ClosureIteration(changed, analyses.size());
  }

  private Set<String> rootsForProgram(
      final TierContext context,
      final ElisionAnalysisModel.ArtifactSnapshot owner,
      final TierCandidate candidate) {
    if (candidate == null || context.release() <= operation.targetRelease()) {
      return context.classesOf(owner);
    }
    final MultiReleaseCandidateInfo info = context.multiReleaseInfo(owner);
    if (info == null) {
      return Set.of();
    }
    final Set<String> roots = new TreeSet<>(info.versionedClasses());
    roots.retainAll(context.classesOf(owner));
    return roots;
  }

  private static boolean retainSameJarTargetClasses(
      final TierCandidate candidate,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final Set<String> tierClasses) {
    boolean changed = false;
    for (final String retained : analysis.retainedClasses()) {
      final String dotted = retained.replace('/', '.');
      if (tierClasses.contains(dotted)) {
        changed |= candidate.roots().add(dotted);
      }
    }
    return changed;
  }

  private ClosureIteration analyzeCandidates(
      final TierContext context,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
      final RootPlan roots,
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses)
      throws IOException {
    boolean changed = false;
    final List<
            Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
        entries = context.candidateEntries();
    final List<DependencyJarTrimmer.TrimAnalysis> analyses =
        ParallelTrimExecutor.mapParallel(
            entries,
            operation.request().policy().trimWorkers(),
            entry -> {
              final TierCandidate candidate = candidates.get(entry.getKey());
              final Set<String> localRoots =
                  candidate.localRoots(context.classesOf(entry.getKey()));
              return candidateAnalysis(candidate, localRoots, entry.getValue());
            });
    for (int index = 0; index < entries.size(); index++) {
      final Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          entry = entries.get(index);
      final ElisionAnalysisModel.ArtifactSnapshot snapshot = entry.getKey();
      final DependencyJarTrimmer.TrimAnalysis analysis = analyses.get(index);
      if (context.release() == operation.targetRelease()) {
        targetAnalyses.put(snapshot.coordinate(), analysis);
      }
      changed |=
          collectReachableClasses(
              analysis.reachableLibraryClasses(), snapshot, context, candidates, roots);
    }
    return new ClosureIteration(changed, analyses.size());
  }

  private static DependencyJarTrimmer.TrimAnalysis candidateAnalysis(
      final TierCandidate candidate,
      final Set<String> localRoots,
      final DependencyJarTrimmer.PreparedAnalysis prepared)
      throws IOException {
    if (candidate.isMultiRelease() && localRoots.isEmpty() && !candidate.roots().isEmpty()) {
      return new DependencyJarTrimmer.TrimAnalysis(
          candidate.classes().size(), Set.of(), Set.of(), Set.of());
    }
    return prepared.analyze(localRoots);
  }

  private boolean collectReachableClasses(
      final Set<String> reachable,
      final ElisionAnalysisModel.ArtifactSnapshot source,
      final TierContext context,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
      final RootPlan roots) {
    boolean changed = false;
    for (final String name : reachable) {
      final String dotted = name.replace('/', '.');
      for (final ElisionAnalysisModel.ArtifactSnapshot owner : context.ownersOf(dotted)) {
        if (owner.equals(source)) {
          continue;
        }
        final TierCandidate candidate = candidates.get(owner);
        if (candidate != null) {
          changed |= candidate.roots().add(dotted);
        } else if (!operation.request().retainedCoordinates().contains(owner.coordinate())) {
          roots.reachableArtifacts().add(owner.coordinate());
        }
      }
    }
    return changed;
  }

  /* package */ record ClosureResult(
      Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses,
      Set<ArtifactCoordinate> reachableArtifacts,
      int analysisRuns) {}

  /* package */ record ClosureIteration(boolean rootsChanged, int analysisRuns) {}
}
