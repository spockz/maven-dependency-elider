/* WHY: Builds the single-release archive view before analysis so root
 * ownership and classpath order stay consistent. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TrimRootPlanner.CommonRootOwners;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Builds a consistent single-release archive and class ownership view. */
final class SingleReleaseTrimInventory {
  private SingleReleaseTrimInventory() {}

  /* package */ record SingleReleaseInventory(
      List<ElisionAnalysisModel.ArtifactSnapshot> artifacts,
      List<ElisionAnalysisModel.ArtifactSnapshot> retainedLibraries,
      Map<ElisionAnalysisModel.ArtifactSnapshot, Path> analysisPaths,
      Map<Path, Set<String>> classesByPath,
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> classesByArtifact,
      Map<String, ElisionAnalysisModel.ArtifactSnapshot> ownerByClass,
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> requestedRoots,
      Map<String, List<ElisionAnalysisModel.ArtifactSnapshot>> toleratedDuplicates) {}

  /* package */ record SingleReleaseLayout(
      Set<ArtifactCoordinate> retainedCoordinates,
      List<ElisionAnalysisModel.ArtifactSnapshot> eligible,
      List<ElisionAnalysisModel.ArtifactSnapshot> candidates,
      List<ElisionAnalysisModel.ArtifactSnapshot> unchangedPrograms,
      Set<ArtifactCoordinate> skippedProgramCoordinates,
      Set<String> unchangedPassThroughClasses) {}

  /* package */ record DynamicRootPlan(
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootsByOwner,
      Set<ArtifactCoordinate> droppedArtifacts) {}

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  /* package */ static SingleReleaseInventory readSingleReleaseInventory(
      final TrimRequest request, final Map<TrimArtifactRootKey, Set<String>> discoveredRoots)
      throws IOException {
    final List<ElisionAnalysisModel.ArtifactSnapshot> artifacts =
        request.candidates().stream()
            .filter(
                snapshot -> MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type()))
            .toList();
    TrimRootPlanner.validateAnalysisInventory(artifacts);
    final Set<ArtifactCoordinate> retainedCoordinates = request.retainedCoordinates();
    final List<ElisionAnalysisModel.ArtifactSnapshot> retainedLibraries =
        artifacts.stream()
            .filter(snapshot -> retainedCoordinates.contains(snapshot.coordinate()))
            .filter(
                snapshot ->
                    MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(
                        snapshot.coordinate().scope()))
            .toList();
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Path> analysisPaths =
        analysisPaths(request, artifacts);
    final Map<Path, Set<String>> classesByPath = TrimCollections.orderedMap();
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> classesByArtifact =
        TrimCollections.orderedMap();
    final Map<String, ElisionAnalysisModel.ArtifactSnapshot> ownerByClass =
        TrimCollections.lookupMap();
    final Map<String, List<ElisionAnalysisModel.ArtifactSnapshot>> toleratedDuplicates =
        new java.util.TreeMap<>();
    populateSingleReleaseClassInventory(
        artifacts,
        analysisPaths,
        classesByPath,
        classesByArtifact,
        ownerByClass,
        new DuplicateTolerance(
            request.policy().duplicateClasses(), retainedCoordinates, toleratedDuplicates));
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> requestedRoots =
        TrimRootPlanner.validateDiscoveredRoots(discoveredRoots, artifacts, classesByPath);
    return new SingleReleaseInventory(
        artifacts,
        retainedLibraries,
        analysisPaths,
        classesByPath,
        classesByArtifact,
        ownerByClass,
        requestedRoots,
        toleratedDuplicates);
  }

  /** Records which owners share each class the user agreed to tolerate. */
  private record DuplicateTolerance(
      DuplicateClassPolicy policy,
      Set<ArtifactCoordinate> retainedCoordinates,
      Map<String, List<ElisionAnalysisModel.ArtifactSnapshot>> owners) {}

  private static void populateSingleReleaseClassInventory(
      final List<ElisionAnalysisModel.ArtifactSnapshot> artifacts,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Path> analysisPaths,
      final Map<Path, Set<String>> classesByPath,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> classesByArtifact,
      final Map<String, ElisionAnalysisModel.ArtifactSnapshot> ownerByClass,
      final DuplicateTolerance tolerance)
      throws IOException {
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : artifacts) {
      final Path source = snapshot.filePath().toAbsolutePath().normalize();
      final Path analysisPath = analysisPaths.getOrDefault(snapshot, source);
      final Set<String> sourceClasses = TrimPaths.classNames(source);
      final Set<String> classes =
          MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope())
              ? TrimPaths.classNames(analysisPath)
              : Set.of();
      classesByPath.put(source, sourceClasses);
      classesByArtifact.put(snapshot, classes);
      for (final String name : classes) {
        registerOwner(name, snapshot, ownerByClass, tolerance);
      }
    }
  }

  private static void registerOwner(
      final String name,
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Map<String, ElisionAnalysisModel.ArtifactSnapshot> ownerByClass,
      final DuplicateTolerance tolerance)
      throws IOException {
    final ElisionAnalysisModel.ArtifactSnapshot previous = ownerByClass.putIfAbsent(name, snapshot);
    if (previous == null || previous.equals(snapshot)) {
      return;
    }
    if (!tolerance.policy().tolerates(name)) {
      throw new IOException("Duplicate class owner in complete JAR inventory: " + name);
    }
    final List<ElisionAnalysisModel.ArtifactSnapshot> owners =
        tolerance.owners().computeIfAbsent(name, ignored -> new java.util.ArrayList<>());
    if (owners.isEmpty()) {
      owners.add(previous);
    }
    owners.add(snapshot);
    if (!tolerance.retainedCoordinates().contains(previous.coordinate())
        && tolerance.retainedCoordinates().contains(snapshot.coordinate())) {
      ownerByClass.put(name, snapshot);
    }
  }

  /* package */ static SingleReleaseLayout singleReleaseLayout(
      final TrimRequest request,
      final SingleReleaseInventory inventory,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException {
    final Set<ArtifactCoordinate> retainedCoordinates = request.retainedCoordinates();
    final Set<ArtifactCoordinate> layoutPassThroughCoordinates = new LinkedHashSet<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory.retainedLibraries()) {
      if (TrimPassThroughPlanner.TRIMMABLE_SCOPES.contains(snapshot.coordinate().scope())
          && TrimPassThroughPlanner.passThroughCoordinate(request, snapshot)) {
        layoutPassThroughCoordinates.add(snapshot.coordinate());
      }
    }
    inventory
        .toleratedDuplicates()
        .forEach(
            (className, owners) -> {
              if (request
                  .policy()
                  .duplicateClasses()
                  .actionFor(className)
                  .filter(DuplicateClassPolicy.Action.RETAIN_JARS::equals)
                  .isPresent()) {
                owners.stream()
                    .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
                    .filter(retainedCoordinates::contains)
                    .forEach(layoutPassThroughCoordinates::add);
              }
            });
    final List<ElisionAnalysisModel.ArtifactSnapshot> eligible =
        inventory.retainedLibraries().stream()
            .filter(
                snapshot ->
                    TrimPassThroughPlanner.TRIMMABLE_SCOPES.contains(snapshot.coordinate().scope()))
            .filter(snapshot -> !layoutPassThroughCoordinates.contains(snapshot.coordinate()))
            .toList();
    final List<ElisionAnalysisModel.ArtifactSnapshot> configuredPassThrough =
        TrimPassThroughPlanner.parsePassThroughArtifacts(
            request.policy().explicitPassThroughCoordinates(),
            inventory.retainedLibraries().stream()
                .filter(
                    snapshot ->
                        TrimPassThroughPlanner.TRIMMABLE_SCOPES.contains(
                            snapshot.coordinate().scope()))
                .toList());
    final Set<String> passThroughIdentities =
        TrimPassThroughPlanner.identities(configuredPassThrough);
    final Set<ArtifactCoordinate> skippedProgramCoordinates =
        new LinkedHashSet<>(layoutPassThroughCoordinates);
    skippedProgramCoordinates.addAll(forcedUnchanged);
    configuredPassThrough.stream()
        .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
        .forEach(skippedProgramCoordinates::add);
    final Set<ArtifactCoordinate> unchangedCoordinates = new LinkedHashSet<>(forcedUnchanged);
    unchangedCoordinates.addAll(layoutPassThroughCoordinates);
    configuredPassThrough.stream()
        .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
        .forEach(unchangedCoordinates::add);
    if (!retainedCoordinates.containsAll(unchangedCoordinates)) {
      throw new IOException("Unchanged analysis set contains an elided artifact");
    }
    final List<ElisionAnalysisModel.ArtifactSnapshot> candidates =
        eligible.stream()
            .filter(snapshot -> !unchangedCoordinates.contains(snapshot.coordinate()))
            .filter(
                snapshot ->
                    !inventory.classesByArtifact().getOrDefault(snapshot, Set.of()).isEmpty())
            .filter(
                snapshot ->
                    !passThroughIdentities.contains(
                        TrimPassThroughPlanner.artifactIdentity(snapshot.coordinate())))
            .sorted(TrimCandidatePlanner.artifactSnapshotOrder())
            .toList();
    final List<ElisionAnalysisModel.ArtifactSnapshot> unchangedPrograms =
        inventory.retainedLibraries().stream()
            .filter(
                snapshot ->
                    !inventory.classesByArtifact().getOrDefault(snapshot, Set.of()).isEmpty())
            .filter(snapshot -> !candidates.contains(snapshot))
            .sorted(TrimCandidatePlanner.artifactSnapshotOrder())
            .toList();
    final Set<String> unchangedPassThroughClasses = new LinkedHashSet<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : configuredPassThrough) {
      unchangedPassThroughClasses.addAll(
          inventory.classesByArtifact().getOrDefault(snapshot, Set.of()));
    }
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory.retainedLibraries()) {
      if (layoutPassThroughCoordinates.contains(snapshot.coordinate())) {
        unchangedPassThroughClasses.addAll(
            inventory.classesByArtifact().getOrDefault(snapshot, Set.of()));
      }
    }
    return new SingleReleaseLayout(
        retainedCoordinates,
        eligible,
        candidates,
        unchangedPrograms,
        skippedProgramCoordinates,
        unchangedPassThroughClasses);
  }

  /* package */ static List<Path> fullClasspath(final SingleReleaseInventory inventory) {
    return inventory.artifacts().stream()
        .filter(
            snapshot ->
                MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(
                    snapshot.coordinate().scope()))
        .map(
            snapshot ->
                inventory
                    .analysisPaths()
                    .getOrDefault(snapshot, snapshot.filePath().toAbsolutePath().normalize()))
        .toList();
  }

  /* package */ static DynamicRootPlan dynamicRootPlan(
      final TrimRequest request,
      final SingleReleaseInventory inventory,
      final SingleReleaseLayout layout,
      final Set<String> platformClasses)
      throws IOException {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootsByOwner =
        TrimCollections.orderedMap();
    final Set<ArtifactCoordinate> droppedArtifacts = new LinkedHashSet<>();
    final DynamicRootContext context =
        new DynamicRootContext(request, inventory, layout, platformClasses);
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory.retainedLibraries()) {
      for (final String root : TrimRootPlanner.dynamicRoots(request, snapshot.filePath())) {
        context.route(root, rootsByOwner, droppedArtifacts);
      }
    }
    return new DynamicRootPlan(rootsByOwner, droppedArtifacts);
  }

  private static Set<ArtifactCoordinate> droppedArtifactCoordinates(
      final SingleReleaseInventory inventory, final SingleReleaseLayout layout) {
    return inventory.artifacts().stream()
        .filter(snapshot -> !layout.retainedCoordinates().contains(snapshot.coordinate()))
        .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
        .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
  }

  /* package */ static Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> candidateRoots(
      final SingleReleaseInventory inventory,
      final SingleReleaseLayout layout,
      final CommonRootOwners commonRootOwners,
      final DynamicRootPlan dynamicRoots) {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> candidateRoots =
        TrimCollections.orderedMap();
    final CandidateRootInputs inputs =
        new CandidateRootInputs(inventory, commonRootOwners, dynamicRoots);
    for (final ElisionAnalysisModel.ArtifactSnapshot candidate : layout.candidates()) {
      candidateRoots.put(candidate, inputs.rootsFor(candidate));
    }
    return candidateRoots;
  }

  private static Map<ElisionAnalysisModel.ArtifactSnapshot, Path> analysisPaths(
      final TrimRequest request, final List<ElisionAnalysisModel.ArtifactSnapshot> inventory)
      throws IOException {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Path> result = TrimCollections.orderedMap();
    final int runtimeRelease = Runtime.version().feature();
    final Path projectionDirectory =
        TrimPaths.analysisLibraryDirectory(request.project(), request.environment());
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory) {
      if (!MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope())) {
        continue;
      }
      final boolean multiRelease =
          MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath());
      final boolean moduleInfo =
          MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath());
      if (multiRelease || moduleInfo) {
        if (request.retainedCoordinates().contains(snapshot.coordinate())) {
          TrimPassThroughPlanner.passThroughCoordinate(request, snapshot);
        }
        result.put(
            snapshot,
            MultiReleaseLibraryProjection.create(
                snapshot.filePath(), snapshot.coordinate(), projectionDirectory, runtimeRelease));
      }
    }
    return result;
  }

  /** Routes one dynamic root through the same retained and unresolved-owner policy. */
  private record DynamicRootContext(
      TrimRequest request,
      SingleReleaseInventory inventory,
      SingleReleaseLayout layout,
      Set<String> platformClasses) {
    private void route(
        final String root,
        final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootsByOwner,
        final Set<ArtifactCoordinate> droppedArtifacts) {
      final ElisionAnalysisModel.ArtifactSnapshot owner = inventory.ownerByClass().get(root);
      if (owner == null) {
        if (request.evidence().projectOutputClasses().contains(root)
            || platformClasses.contains(root)) {
          return;
        }
        droppedArtifacts.addAll(droppedArtifactCoordinates(inventory, layout));
        return;
      }
      if (layout.retainedCoordinates().contains(owner.coordinate())) {
        if (layout.eligible().contains(owner)) {
          rootsByOwner.computeIfAbsent(owner, ignored -> new TreeSet<>()).add(root);
        }
      } else {
        droppedArtifacts.add(owner.coordinate());
      }
    }
  }

  /** Merges requested, common, and dynamic roots before the empty-root fallback. */
  private record CandidateRootInputs(
      SingleReleaseInventory inventory,
      CommonRootOwners commonRootOwners,
      DynamicRootPlan dynamicRoots) {
    private Set<String> rootsFor(final ElisionAnalysisModel.ArtifactSnapshot candidate) {
      final Set<String> roots =
          new TreeSet<>(inventory.requestedRoots().getOrDefault(candidate, Set.of()));
      roots.addAll(commonRootOwners.byArtifact().getOrDefault(candidate, Set.of()));
      roots.addAll(dynamicRoots.rootsByOwner().getOrDefault(candidate, Set.of()));
      inventory
          .toleratedDuplicates()
          .forEach(
              (className, owners) -> {
                if (owners.contains(candidate)) {
                  roots.add(className);
                }
              });
      if (roots.isEmpty()) {
        roots.addAll(inventory.classesByArtifact().getOrDefault(candidate, Set.of()));
      }
      return roots;
    }
  }
}
