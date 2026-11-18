/* WHY: Streams unchanged program JARs with ASM in conservative mode without ProGuard pools. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierCandidatePlanner.TierCandidate;
import io.github.spockz.elider.plugin.TierRootPlanner.RootPlan;
import io.github.spockz.elider.scanner.ArchiveClassScanner;
import io.github.spockz.elider.trimmer.ClosureQueryPolicy;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Streams unchanged program JARs with ASM for conservative closure propagation. */
final class UnchangedProgramClosureAnalyzer {
  /** Workers count from the active trim request. */
  private final int workers;

  /** Tracks scanned internal names per tier and owner so each class is parsed once. */
  private final Map<TierOwnerKey, Set<String>> scannedByOwner = new ConcurrentHashMap<>();

  /* package */ UnchangedProgramClosureAnalyzer(final int workers) {
    this.workers = workers;
  }

  /* package */ static boolean supports(final TrimRequest request) {
    return request.evidence().runtimePolicy().closureQueryPolicy().mode()
        == ClosureQueryPolicy.Mode.CONSERVATIVE;
  }

  /* package */ TierClosureAnalyzer.ClosureIteration analyzePrograms(
      final TierClosureAnalyzer analyzer,
      final TierContext context,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
      final RootPlan roots,
      final Map<ArtifactCoordinate, Set<String>> liveProgramClasses)
      throws IOException {
    final List<ScanTask> tasks = new ArrayList<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot owner : roots.programRoots().keySet()) {
      collectTask(context, owner, roots, liveProgramClasses, tasks);
    }
    if (tasks.isEmpty()) {
      return new TierClosureAnalyzer.ClosureIteration(false, 0);
    }
    final List<ScanOutcome> outcomes =
        ParallelTrimExecutor.mapParallel(tasks, workers, UnchangedProgramClosureAnalyzer::scanTask);
    boolean changed = false;
    for (int index = 0; index < tasks.size(); index++) {
      final ScanTask task = tasks.get(index);
      final ScanOutcome outcome = outcomes.get(index);
      task.alreadyScanned().addAll(outcome.visitedInternal());
      final Set<String> liveClasses = liveProgramClasses.get(task.owner().coordinate());
      if (liveClasses != null) {
        liveClasses.addAll(outcome.visitedInternal());
      }
      changed |=
          analyzer.collectReachableClasses(
              outcome.externalDotted(), task.owner(), context, candidates, roots);
    }
    return new TierClosureAnalyzer.ClosureIteration(changed, outcomes.size());
  }

  private void collectTask(
      final TierContext context,
      final ElisionAnalysisModel.ArtifactSnapshot owner,
      final RootPlan roots,
      final Map<ArtifactCoordinate, Set<String>> liveProgramClasses,
      final List<ScanTask> tasks) {
    final TierOwnerKey key = new TierOwnerKey(context.release(), owner.coordinate());
    final Set<String> scanned =
        scannedByOwner.computeIfAbsent(key, ignored -> new LinkedHashSet<>());
    final Set<String> liveClasses = liveProgramClasses.get(owner.coordinate());
    if (liveClasses != null && !scanned.isEmpty()) {
      liveClasses.addAll(scanned);
    }
    final Set<String> pending = pendingInternalNames(context, owner, roots, scanned);
    if (!pending.isEmpty()) {
      tasks.add(new ScanTask(context, owner, pending, scanned));
    }
  }

  private static Set<String> pendingInternalNames(
      final TierContext context,
      final ElisionAnalysisModel.ArtifactSnapshot owner,
      final RootPlan roots,
      final Set<String> scanned) {
    final Set<String> tierClasses = context.classesOf(owner);
    if (tierClasses.isEmpty()) {
      return Set.of();
    }
    final Set<String> requested =
        roots.wholeJarPrograms().contains(owner) ? tierClasses : roots.programRoots().get(owner);
    if (requested == null || requested.isEmpty()) {
      return Set.of();
    }
    final Set<String> pending = new LinkedHashSet<>();
    for (final String dotted : requested) {
      if (tierClasses.contains(dotted)) {
        final String internal = dotted.replace('.', '/');
        if (!scanned.contains(internal)) {
          pending.add(internal);
        }
      }
    }
    return pending;
  }

  private static ScanOutcome scanTask(final ScanTask task) throws IOException {
    final Set<String> tierClasses = task.context().classesOf(task.owner());
    final Set<String> visitedInternal = new LinkedHashSet<>();
    final Set<String> externalDotted = new LinkedHashSet<>();
    Set<String> frontier = task.pendingInternal();
    while (!frontier.isEmpty()) {
      final Map<String, Set<String>> perClass =
          ArchiveClassScanner.scanSelected(task.context().pathFor(task.owner()), frontier);
      visitedInternal.addAll(frontier);
      frontier =
          collectNextFrontier(
              perClass, tierClasses, task.alreadyScanned(), visitedInternal, externalDotted);
    }
    return new ScanOutcome(visitedInternal, externalDotted);
  }

  private static Set<String> collectNextFrontier(
      final Map<String, Set<String>> perClass,
      final Set<String> tierClasses,
      final Set<String> alreadyScanned,
      final Set<String> visitedInternal,
      final Set<String> externalDotted) {
    final Set<String> nextFrontier = new LinkedHashSet<>();
    for (final Set<String> references : perClass.values()) {
      for (final String targetDotted : references) {
        if (tierClasses.contains(targetDotted)) {
          final String internal = targetDotted.replace('.', '/');
          if (!alreadyScanned.contains(internal) && !visitedInternal.contains(internal)) {
            nextFrontier.add(internal);
          }
        } else {
          externalDotted.add(targetDotted);
        }
      }
    }
    return nextFrontier;
  }

  private record TierOwnerKey(int release, ArtifactCoordinate coordinate) {}

  private record ScanTask(
      TierContext context,
      ElisionAnalysisModel.ArtifactSnapshot owner,
      Set<String> pendingInternal,
      Set<String> alreadyScanned) {}

  private record ScanOutcome(Set<String> visitedInternal, Set<String> externalDotted) {}
}
