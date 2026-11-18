/* WHY: Combines required roots only after their owners are resolved across
 * all analyzed release tiers. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierInventoryReader.Inventory;
import io.github.spockz.elider.plugin.TierInventoryReader.MultiReleaseCandidateInfo;
import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import proguard.classfile.ClassPool;

/** Combines roots after resolving their owners across analyzed tiers. */
final class TierRootPlanner {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierRootPlanner(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ RootPlan findRoots(
      final Inventory inventory,
      final List<TierContext> projections,
      final Map<Integer, ClassPool> platforms)
      throws IOException {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> requested =
        TrimRootPlanner.validateDiscoveredRoots(
            operation.discoveredRoots(), inventory.snapshots(), inventory.classesBySourcePath());
    validateStrictRoots(projections, platforms.values());
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots =
        findCandidateSnapshots(
            inventory.passThrough(), projections, inventory.multiReleaseCandidates());
    final Set<ElisionAnalysisModel.ArtifactSnapshot> candidates = Set.copyOf(snapshots);
    final List<ElisionAnalysisModel.ArtifactSnapshot> retainedLibraries =
        TrimPassThroughPlanner.retainedAnalysisLibraries(operation.request());
    final List<ElisionAnalysisModel.ArtifactSnapshot> unchangedPrograms =
        retainedLibraries.stream().filter(snapshot -> !candidates.contains(snapshot)).toList();
    final Set<ArtifactCoordinate> retainJarOwners = retainJarDuplicateOwners(projections);
    final Set<ElisionAnalysisModel.ArtifactSnapshot> wholeJarPrograms =
        unchangedPrograms.stream()
            .filter(
                snapshot ->
                    !operation.request().policy().trimEnabled()
                        || TrimPassThroughPlanner.unchangedScope(snapshot.coordinate())
                        || retainJarOwners.contains(snapshot.coordinate()))
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots =
        emptyCandidateRoots(snapshots);
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> programRoots =
        emptyCandidateRoots(unchangedPrograms);
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> allRoots =
        LinkedHashMap.newLinkedHashMap(snapshots.size() + unchangedPrograms.size());
    allRoots.putAll(roots);
    allRoots.putAll(programRoots);
    final Set<ArtifactCoordinate> reachable = new LinkedHashSet<>();
    final TierRootResolution resolution = new TierRootResolution(operation);
    final Set<String> duplicates =
        projections.stream()
            .flatMap(projection -> projection.ownersByClass().entrySet().stream())
            .filter(entry -> entry.getValue().size() > 1)
            .map(Map.Entry::getKey)
            .collect(java.util.stream.Collectors.toSet());
    resolution.addCommonRoots(duplicates, projections, allRoots, reachable);
    resolution.addCommonRoots(
        TrimRootPlanner.commonRoots(operation.request()), projections, allRoots, reachable);
    resolution.addRequestedRoots(requested, projections, allRoots);
    resolution.addDynamicRoots(retainedLibraries, projections, allRoots, reachable);
    addRequiredTargetRoots(inventory.multiReleaseCandidates(), roots);
    return new RootPlan(snapshots, candidates, wholeJarPrograms, roots, programRoots, reachable);
  }

  private static boolean isPlatformClass(
      final Iterable<ClassPool> classTables, final String binaryClassName) {
    final String internalName = binaryClassName.replace('.', '/');
    for (final ClassPool jdkClassTable : classTables) {
      if (jdkClassTable.getClass(internalName) != null) {
        return true;
      }
    }
    return false;
  }

  private void validateStrictRoots(
      final List<TierContext> projections, final Iterable<ClassPool> platforms) throws IOException {
    final Set<String> roots = new HashSet<>();
    operation.request().evidence().sourceRoots().forEach(root -> roots.add(root.replace('/', '.')));
    operation
        .request()
        .evidence()
        .bytecodeRoots()
        .forEach(root -> roots.add(root.replace('/', '.')));
    operation.request().policy().explicitRoots().forEach(root -> roots.add(root.replace('/', '.')));
    for (final String root : roots) {
      if (operation.request().evidence().projectOutputClasses().contains(root)
          || isPlatformClass(platforms, root)) {
        continue;
      }
      if (projections.stream().noneMatch(context -> context.ownerOf(root) != null)) {
        throw new IOException("Required class root has no recognized owner: " + root);
      }
    }
  }

  private Set<ArtifactCoordinate> retainJarDuplicateOwners(final List<TierContext> projections) {
    final DuplicateClassPolicy policy = operation.request().policy().duplicateClasses();
    if (policy.isEmpty()) {
      return Set.of();
    }
    final Set<ArtifactCoordinate> retainedOwners = new HashSet<>();
    for (final TierContext projection : projections) {
      projection
          .ownersByClass()
          .forEach(
              (className, owners) -> {
                if (owners.size() > 1
                    && policy
                        .actionFor(className)
                        .filter(DuplicateClassPolicy.Action.RETAIN_JARS::equals)
                        .isPresent()) {
                  owners.forEach(owner -> retainedOwners.add(owner.coordinate()));
                }
              });
    }
    return Set.copyOf(retainedOwners);
  }

  private List<ElisionAnalysisModel.ArtifactSnapshot> findCandidateSnapshots(
      final TrimPassThroughPlan passThrough,
      final List<TierContext> projections,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> multiRelease) {
    if (!operation.request().policy().trimEnabled()) {
      return List.of();
    }
    final Set<ArtifactCoordinate> retainJarOwners = retainJarDuplicateOwners(projections);
    return passThrough.retained().stream()
        .filter(snapshot -> !operation.forcedUnchanged().contains(snapshot.coordinate()))
        .filter(snapshot -> !retainJarOwners.contains(snapshot.coordinate()))
        .filter(
            snapshot ->
                !TierAnalysisViews.classesInTargetTier(snapshot, projections).isEmpty()
                    || multiRelease.containsKey(snapshot))
        .sorted(TrimCandidatePlanner.artifactSnapshotOrder())
        .toList();
  }

  private static Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> emptyCandidateRoots(
      final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots) {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    snapshots.forEach(snapshot -> roots.put(snapshot, new TreeSet<>()));
    return roots;
  }

  private static void addRequiredTargetRoots(
      final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> candidates,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots) {
    candidates.forEach(
        (snapshot, info) -> {
          final Set<String> candidateRoots = roots.get(snapshot);
          if (candidateRoots != null) {
            candidateRoots.addAll(info.requiredTargetRoots());
          }
        });
  }

  /* package */ record RootPlan(
      List<ElisionAnalysisModel.ArtifactSnapshot> candidateSnapshots,
      Set<ElisionAnalysisModel.ArtifactSnapshot> candidateSet,
      Set<ElisionAnalysisModel.ArtifactSnapshot> wholeJarPrograms,
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots,
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> programRoots,
      Set<ArtifactCoordinate> reachableArtifacts) {}
}
