/* WHY: Propagates candidate and unchanged-program references across tiers
 * until no roots change. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierCandidatePlanner.TierCandidate;
import io.github.spockz.elider.plugin.TierRootPlanner.RootPlan;
import io.github.spockz.elider.trimmer.ClosureQueryPolicy;
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

  /** Immutable class-edge policy reused across the tier fixed-point passes. */
  private final ClosureQueryPolicy closureQueryPolicy;

  /** Streams unchanged program JARs with ASM in conservative mode. */
  private final UnchangedProgramClosureAnalyzer unchangedAnalyzer;

  /* package */ TierClosureAnalyzer(final MultiReleaseTrimContext operation) {
    this.operation = operation;
    this.closureQueryPolicy = operation.request().evidence().runtimePolicy().closureQueryPolicy();
    this.unchangedAnalyzer =
        this.closureQueryPolicy.mode() == ClosureQueryPolicy.Mode.CONSERVATIVE
            ? new UnchangedProgramClosureAnalyzer(operation.request().policy().trimWorkers())
            : null;
  }

  /* package */ ClosureResult analyzeToFixedPoint(
      final List<TierContext> contexts,
      final RootPlan roots,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates)
      throws IOException {
    final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    final Map<ArtifactCoordinate, Set<String>> liveProgramClasses =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    roots
        .programRoots()
        .keySet()
        .forEach(program -> liveProgramClasses.put(program.coordinate(), new TreeSet<>()));
    int analysisRuns = 0;
    boolean changed;
    do {
      for (final Set<String> liveClasses : liveProgramClasses.values()) {
        liveClasses.clear();
      }
      final ClosureIteration iteration =
          analyzeIteration(contexts, roots, candidates, targetAnalyses, liveProgramClasses);
      changed = iteration.rootsChanged();
      analysisRuns += iteration.analysisRuns();
    } while (changed);
    final Map<ArtifactCoordinate, Set<String>> immutableLiveProgramClasses =
        LinkedHashMap.newLinkedHashMap(liveProgramClasses.size());
    for (final Map.Entry<ArtifactCoordinate, Set<String>> entry : liveProgramClasses.entrySet()) {
      immutableLiveProgramClasses.put(entry.getKey(), Set.copyOf(entry.getValue()));
    }
    return new ClosureResult(
        targetAnalyses,
        roots.reachableArtifacts(),
        analysisRuns,
        Map.copyOf(immutableLiveProgramClasses));
  }

  private ClosureIteration analyzeIteration(
      final List<TierContext> contexts,
      final RootPlan roots,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses,
      final Map<ArtifactCoordinate, Set<String>> liveProgramClasses)
      throws IOException {
    boolean changed = false;
    int runs = 0;
    for (final TierContext context : contexts) {
      if (unchangedAnalyzer != null) {
        final ClosureIteration unchanged =
            unchangedAnalyzer.analyzePrograms(this, context, candidates, roots, liveProgramClasses);
        changed |= unchanged.rootsChanged();
        runs += unchanged.analysisRuns();
      }
      final ClosureIteration programs =
          analyzePrograms(context, candidates, roots, liveProgramClasses);
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
      final RootPlan roots,
      final Map<ArtifactCoordinate, Set<String>> liveProgramClasses)
      throws IOException {
    boolean changed = false;
    final List<
            Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
        entries =
            context.programEntries().stream()
                .filter(
                    entry ->
                        !rootsForProgram(
                                context, entry.getKey(), candidates.get(entry.getKey()), roots)
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
                        rootsForProgram(
                            context, entry.getKey(), candidates.get(entry.getKey()), roots),
                        closureQueryPolicy));
    for (int index = 0; index < entries.size(); index++) {
      final Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          entry = entries.get(index);
      final ElisionAnalysisModel.ArtifactSnapshot owner = entry.getKey();
      final TierCandidate candidate = candidates.get(owner);
      final DependencyJarTrimmer.TrimAnalysis analysis = analyses.get(index);
      final Set<String> liveClasses = liveProgramClasses.get(owner.coordinate());
      if (liveClasses != null) {
        liveClasses.addAll(analysis.retainedClasses());
      }
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
      final TierCandidate candidate,
      final RootPlan rootPlan) {
    if (candidate == null) {
      if (rootPlan.wholeJarPrograms().contains(owner)) {
        return context.classesOf(owner);
      }
      final Set<String> liveRoots = rootPlan.programRoots().get(owner);
      if (liveRoots == null || liveRoots.isEmpty()) {
        return Set.of();
      }
      final Set<String> scoped = new TreeSet<>(liveRoots);
      scoped.retainAll(context.classesOf(owner));
      return scoped;
    }
    if (context.release() <= operation.targetRelease()) {
      return context.classesOf(owner);
    }
    final Set<String> versioned = context.versionedClassesOf(owner);
    if (versioned.isEmpty()) {
      return Set.of();
    }
    final Set<String> roots = new TreeSet<>(versioned);
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
              try {
                return candidateAnalysis(
                    candidate, localRoots, entry.getValue(), closureQueryPolicy);
              } catch (final DependencyJarTrimmer.UnresolvedReferenceException exception) {
                throw new CandidateUnresolvedReferenceException(
                    entry.getKey().coordinate(), exception);
              }
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
      final DependencyJarTrimmer.PreparedAnalysis prepared,
      final ClosureQueryPolicy queryPolicy)
      throws IOException {
    if (candidate.isMultiRelease() && localRoots.isEmpty() && !candidate.roots().isEmpty()) {
      return new DependencyJarTrimmer.TrimAnalysis(
          candidate.classes().size(), Set.of(), Set.of(), Set.of());
    }
    return prepared.analyze(localRoots, queryPolicy);
  }

  /* package */ boolean collectReachableClasses(
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
        } else if (roots.programRoots().containsKey(owner)) {
          changed |= roots.programRoots().get(owner).add(dotted);
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
      int analysisRuns,
      Map<ArtifactCoordinate, Set<String>> liveProgramClasses) {}

  /* package */ record ClosureIteration(boolean rootsChanged, int analysisRuns) {}

  /** Carries the failing candidate coordinate for pass-through demotion. */
  /* package */ static final class CandidateUnresolvedReferenceException extends IOException {
    private static final long serialVersionUID = 1L;

    /** Coordinate of the candidate whose closure hit an unresolved reference. */
    private final ArtifactCoordinate candidateCoordinate;

    /* package */ CandidateUnresolvedReferenceException(
        final ArtifactCoordinate coordinate,
        final DependencyJarTrimmer.UnresolvedReferenceException cause) {
      super(cause.getMessage(), cause);
      this.candidateCoordinate = coordinate;
    }

    /* package */ ArtifactCoordinate coordinate() {
      return candidateCoordinate;
    }
  }
}
