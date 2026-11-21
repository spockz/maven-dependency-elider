/* WHY: Computes conservative reachability without ProGuard pools when trimming is disabled. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.scanner.ProductionBytecodeReferenceScanner;
import io.github.spockz.elider.trimmer.ClosureQueryPolicy;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Streams JAR bytecode with ASM for conservative no-trim reachability. */
final class NoTrimClosureAnalyzer {
  private NoTrimClosureAnalyzer() {}

  /* package */ static boolean supports(final TrimRequest request) {
    return !request.policy().trimEnabled()
        && request.evidence().runtimePolicy().closureQueryPolicy().mode()
            == ClosureQueryPolicy.Mode.CONSERVATIVE;
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  /* package */ static TierClosureAnalyzer.ClosureResult analyze(
      final MultiReleaseTrimContext operation,
      final List<TierArchiveProjector.TierContext> projections,
      final TierRootPlanner.RootPlan roots)
      throws IOException {
    final Set<ArtifactCoordinate> retained = operation.request().retainedCoordinates();
    final Set<ArtifactCoordinate> reachable = new LinkedHashSet<>(roots.reachableArtifacts());
    final List<TierProgramScan> work = new ArrayList<>();
    final Set<Integer> scheduledViews = new HashSet<>();
    for (final TierArchiveProjector.TierContext projection : projections) {
      if (!scheduledViews.add(projection.release())) {
        continue;
      }
      for (final ElisionAnalysisModel.ArtifactSnapshot owner : roots.wholeJarPrograms()) {
        if (!projection.classesOf(owner).isEmpty()) {
          work.add(new TierProgramScan(projection, owner));
        }
      }
    }
    final List<ScanOutcome> scanned =
        ParallelTrimExecutor.mapParallel(
            work,
            operation.request().policy().trimWorkers(),
            item -> scanWholeProgramReferences(item.projection(), item.owner(), retained));
    final Map<Integer, TierRequiredHierarchy> hierarchyByRelease = new HashMap<>();
    for (final ScanOutcome outcome : scanned) {
      reachable.addAll(outcome.reachable());
      TierRequiredHierarchy.addToRelease(
          hierarchyByRelease, outcome.release(), outcome.hierarchy());
    }
    TierRequiredHierarchy.verify(
        operation.request(), projections, roots.linkageRoots(), hierarchyByRelease, null);
    return new TierClosureAnalyzer.ClosureResult(
        Map.of(), Set.copyOf(reachable), work.size(), Map.of());
  }

  private static ScanOutcome scanWholeProgramReferences(
      final TierArchiveProjector.TierContext projection,
      final ElisionAnalysisModel.ArtifactSnapshot owner,
      final Set<ArtifactCoordinate> retained)
      throws IOException {
    final Set<String> internalNames = new LinkedHashSet<>();
    for (final String dotted : projection.classesOf(owner)) {
      internalNames.add(dotted.replace('.', '/'));
    }
    final Set<ArtifactCoordinate> reached = new LinkedHashSet<>();
    final TierRequiredHierarchy hierarchy = new TierRequiredHierarchy();
    final Set<String> references =
        new ProductionBytecodeReferenceScanner()
            .scanArchive(projection.pathFor(owner), internalNames, hierarchy::record)
            .referencedClasses();
    for (final String ref : references) {
      for (final ElisionAnalysisModel.ArtifactSnapshot targetOwner : projection.ownersOf(ref)) {
        if (!owner.equals(targetOwner) && !retained.contains(targetOwner.coordinate())) {
          reached.add(targetOwner.coordinate());
        }
      }
    }
    return new ScanOutcome(projection.release(), reached, hierarchy);
  }

  private record TierProgramScan(
      TierArchiveProjector.TierContext projection, ElisionAnalysisModel.ArtifactSnapshot owner) {}

  private record ScanOutcome(
      int release, Set<ArtifactCoordinate> reachable, TierRequiredHierarchy hierarchy) {}
}
