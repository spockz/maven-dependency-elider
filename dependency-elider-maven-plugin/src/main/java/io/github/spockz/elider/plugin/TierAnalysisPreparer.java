/* WHY: Prepares isolated candidate and unchanged-program pools against the
 * same tier siblings and platform. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierCandidatePlanner.TierCandidate;
import io.github.spockz.elider.plugin.TierInventoryReader.Inventory;
import io.github.spockz.elider.plugin.TierRootPlanner.RootPlan;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.TrimAnalysisSession;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Prepares isolated pools for each analyzed runtime tier. */
final class TierAnalysisPreparer {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierAnalysisPreparer(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ List<TierContext> prepareContexts(
      final Inventory inventory,
      final List<TierContext> projections,
      final RootPlan roots,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates)
      throws IOException {
    final Set<String> skipped = skippedIdentities(inventory.passThrough());
    final Set<String> unchangedClasses = unchangedPassThroughClasses(projections, skipped);
    final List<ElisionAnalysisModel.ArtifactSnapshot> unchangedPrograms =
        inventory.passThrough().retainedLibraries().stream()
            .filter(snapshot -> !roots.candidateSet().contains(snapshot))
            .toList();
    final List<TierContext> contexts = new ArrayList<>();
    final DependencyJarTrimmer trimmer = new DependencyJarTrimmer();
    for (final TierContext projection : projections) {
      contexts.add(
          prepareContext(
              projection,
              inventory,
              roots.candidateSnapshots(),
              unchangedPrograms,
              candidates,
              skipped,
              unchangedClasses,
              trimmer));
    }
    return List.copyOf(contexts);
  }

  private Set<String> skippedIdentities(final TrimPassThroughPlan plan) {
    final Set<String> skipped = new LinkedHashSet<>(plan.skippedArtifactIdentities());
    operation
        .forcedUnchanged()
        .forEach(coordinate -> skipped.add(TrimPassThroughPlanner.artifactIdentity(coordinate)));
    return skipped;
  }

  private Set<String> unchangedPassThroughClasses(
      final List<TierContext> projections, final Set<String> skippedIdentities) {
    final Set<String> classes = new LinkedHashSet<>();
    for (final TierContext projection : projections) {
      for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
          operation.request().candidates()) {
        if (skippedIdentities.contains(
            TrimPassThroughPlanner.artifactIdentity(snapshot.coordinate()))) {
          classes.addAll(projection.classesOf(snapshot));
        }
      }
    }
    return classes;
  }

  private TierContext prepareContext(
      final TierContext projection,
      final Inventory inventory,
      final List<ElisionAnalysisModel.ArtifactSnapshot> candidateSnapshots,
      final List<ElisionAnalysisModel.ArtifactSnapshot> unchangedPrograms,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
      final Set<String> skippedIdentities,
      final Set<String> unchangedClasses,
      final DependencyJarTrimmer trimmer)
      throws IOException {
    final TrimAnalysisSession session = new TrimAnalysisSession(trimmer);
    final Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        candidatePrepared =
            prepareCandidateAnalyses(
                projection,
                inventory.snapshots(),
                candidateSnapshots,
                candidates,
                unchangedClasses,
                session);
    final Set<ElisionAnalysisModel.ArtifactSnapshot> programSnapshots =
        programSnapshots(projection.release(), candidateSnapshots, unchangedPrograms, candidates);
    final Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        programPrepared =
            prepareProgramAnalyses(
                projection,
                inventory.snapshots(),
                programSnapshots,
                skippedIdentities,
                unchangedClasses,
                session);
    return projection.withPrepared(candidatePrepared, programPrepared);
  }

  private Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
      prepareCandidateAnalyses(
          final TierContext projection,
          final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
          final List<ElisionAnalysisModel.ArtifactSnapshot> candidateSnapshots,
          final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
          final Set<String> unchangedClasses,
          final TrimAnalysisSession session)
          throws IOException {
    final List<ElisionAnalysisModel.ArtifactSnapshot> preparable =
        candidateSnapshots.stream()
            .filter(
                snapshot ->
                    !(candidates.get(snapshot).isMultiRelease()
                        && projection.release() > operation.targetRelease()))
            .filter(snapshot -> !projection.classesOf(snapshot).isEmpty())
            .sorted(TrimCandidatePlanner.artifactSnapshotOrder())
            .toList();
    final List<DependencyJarTrimmer.PreparedAnalysis> results =
        ParallelTrimExecutor.mapParallel(
            preparable,
            operation.request().policy().trimWorkers(),
            snapshot -> {
              final List<Path> siblings =
                  TierAnalysisViews.tierSiblings(inventory, projection, snapshot);
              return session.prepareWithUnchangedPassThroughLibraries(
                  projection.pathFor(snapshot), siblings, projection.platform(), unchangedClasses);
            });
    final Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        prepared =
            LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    for (int index = 0; index < preparable.size(); index++) {
      prepared.put(preparable.get(index), results.get(index));
    }
    return prepared;
  }

  private Set<ElisionAnalysisModel.ArtifactSnapshot> programSnapshots(
      final int release,
      final List<ElisionAnalysisModel.ArtifactSnapshot> candidateSnapshots,
      final List<ElisionAnalysisModel.ArtifactSnapshot> unchangedPrograms,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates) {
    final Set<ElisionAnalysisModel.ArtifactSnapshot> programs =
        new LinkedHashSet<>(unchangedPrograms);
    if (release > operation.targetRelease()) {
      candidateSnapshots.stream()
          .filter(snapshot -> candidates.get(snapshot).isMultiRelease())
          .forEach(programs::add);
    }
    return programs;
  }

  private Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
      prepareProgramAnalyses(
          final TierContext projection,
          final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
          final Set<ElisionAnalysisModel.ArtifactSnapshot> programs,
          final Set<String> skippedIdentities,
          final Set<String> unchangedClasses,
          final TrimAnalysisSession session)
          throws IOException {
    final List<ElisionAnalysisModel.ArtifactSnapshot> preparable =
        programs.stream()
            .filter(snapshot -> !projection.classesOf(snapshot).isEmpty())
            .sorted(TrimCandidatePlanner.artifactSnapshotOrder())
            .toList();
    final List<DependencyJarTrimmer.PreparedAnalysis> results =
        ParallelTrimExecutor.mapParallel(
            preparable,
            operation.request().policy().trimWorkers(),
            snapshot ->
                prepareProgram(
                    snapshot, projection, inventory, skippedIdentities, unchangedClasses, session));
    final Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        prepared =
            LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    for (int index = 0; index < preparable.size(); index++) {
      prepared.put(preparable.get(index), results.get(index));
    }
    return prepared;
  }

  private DependencyJarTrimmer.PreparedAnalysis prepareProgram(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final TierContext projection,
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
      final Set<String> skippedIdentities,
      final Set<String> unchangedClasses,
      final TrimAnalysisSession session)
      throws IOException {
    final List<Path> siblings = TierAnalysisViews.tierSiblings(inventory, projection, snapshot);
    final Path programPath = projection.pathFor(snapshot);
    if (skippedIdentities.contains(
        TrimPassThroughPlanner.artifactIdentity(snapshot.coordinate()))) {
      return session.prepareUnchangedPassThrough(
          programPath, siblings, projection.platform(), unchangedClasses);
    }
    return session.prepareWithUnchangedPassThroughLibraries(
        programPath, siblings, projection.platform(), unchangedClasses);
  }
}
