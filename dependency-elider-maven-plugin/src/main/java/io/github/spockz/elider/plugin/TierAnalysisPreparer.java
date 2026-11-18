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
import java.util.Objects;
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
        TrimPassThroughPlanner.retainedAnalysisLibraries(operation.request()).stream()
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
    TrimPassThroughPlanner.retainedAnalysisLibraries(operation.request()).stream()
        .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
        .filter(
            coordinate ->
                !operation.request().policy().trimEnabled()
                    || TrimPassThroughPlanner.unchangedScope(coordinate))
        .map(TrimPassThroughPlanner::artifactIdentity)
        .forEach(skipped::add);
    return skipped;
  }

  private Set<String> unchangedPassThroughClasses(
      final List<TierContext> projections, final Set<String> skippedIdentities) {
    final Set<String> classes = new LinkedHashSet<>();
    // Reached dropped owners are promoted unchanged after tier closure returns.
    for (final TierContext projection : projections) {
      for (final ElisionAnalysisModel.ArtifactSnapshot snapshot :
          operation.request().candidates()) {
        if (skippedIdentities.contains(
                TrimPassThroughPlanner.artifactIdentity(snapshot.coordinate()))
            || !operation.request().retainedCoordinates().contains(snapshot.coordinate())) {
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
    final TrimAnalysisSession.SharedTierContext sharedTier =
        sharedTierContext(projection, inventory, session);
    final Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        candidatePrepared =
            prepareCandidateAnalyses(
                projection,
                inventory.snapshots(),
                candidateSnapshots,
                candidates,
                unchangedClasses,
                session,
                sharedTier);
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
                session,
                sharedTier);
    return projection.withPrepared(candidatePrepared, programPrepared);
  }

  private static TrimAnalysisSession.SharedTierContext sharedTierContext(
      final TierContext projection, final Inventory inventory, final TrimAnalysisSession session) {
    final boolean hasDuplicateOwners =
        projection.ownersByClass().values().stream().anyMatch(owners -> owners.size() > 1);
    if (hasDuplicateOwners) {
      return null;
    }
    final List<Path> tierArchives =
        inventory.snapshots().stream()
            .filter(
                snapshot ->
                    MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(
                        snapshot.coordinate().scope()))
            .map(projection::pathFor)
            .filter(Objects::nonNull)
            .toList();
    return session.prepareSharedTierContext(tierArchives, projection.jdkClassTable());
  }

  private Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
      prepareCandidateAnalyses(
          final TierContext projection,
          final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
          final List<ElisionAnalysisModel.ArtifactSnapshot> candidateSnapshots,
          final Map<ElisionAnalysisModel.ArtifactSnapshot, TierCandidate> candidates,
          final Set<String> unchangedClasses,
          final TrimAnalysisSession session,
          final TrimAnalysisSession.SharedTierContext sharedTier)
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
              final boolean allowModular =
                  MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY.equals(
                      operation.request().policy().mrjarStrategy());
              final boolean tolerateUnresolved =
                  !operation.request().policy().trimPassThroughOnUnresolved();
              return sharedTier != null
                  ? sharedTier.prepareWithUnchangedPassThroughLibraries(
                      projection.pathFor(snapshot),
                      siblings,
                      unchangedClasses,
                      allowModular,
                      tolerateUnresolved)
                  : session.prepareWithUnchangedPassThroughLibraries(
                      projection.pathFor(snapshot),
                      siblings,
                      projection.jdkClassTable(),
                      unchangedClasses,
                      allowModular,
                      tolerateUnresolved);
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
          final TrimAnalysisSession session,
          final TrimAnalysisSession.SharedTierContext sharedTier)
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
                    snapshot,
                    projection,
                    inventory,
                    skippedIdentities,
                    unchangedClasses,
                    session,
                    sharedTier));
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
      final TrimAnalysisSession session,
      final TrimAnalysisSession.SharedTierContext sharedTier)
      throws IOException {
    final List<Path> siblings = TierAnalysisViews.tierSiblings(inventory, projection, snapshot);
    final Path programPath = projection.pathFor(snapshot);
    final boolean skipped =
        skippedIdentities.contains(TrimPassThroughPlanner.artifactIdentity(snapshot.coordinate()));
    if (sharedTier != null) {
      return skipped
          ? sharedTier.prepareUnchangedPassThrough(programPath, siblings, unchangedClasses)
          : sharedTier.prepareWithUnchangedPassThroughLibraries(
              programPath, siblings, unchangedClasses, false);
    }
    return skipped
        ? session.prepareUnchangedPassThrough(
            programPath, siblings, projection.jdkClassTable(), unchangedClasses)
        : session.prepareWithUnchangedPassThroughLibraries(
            programPath, siblings, projection.jdkClassTable(), unchangedClasses);
  }
}
