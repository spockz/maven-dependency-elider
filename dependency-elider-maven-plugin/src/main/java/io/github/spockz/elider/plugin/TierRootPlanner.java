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
    final Set<String> platformNames = platformClassNames(platforms.values());
    validateStrictRoots(projections, platformNames);
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots =
        findCandidateSnapshots(
            inventory.passThrough(), projections, inventory.multiReleaseCandidates());
    final Set<ElisionAnalysisModel.ArtifactSnapshot> candidates = Set.copyOf(snapshots);
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots =
        emptyCandidateRoots(snapshots);
    final Set<ArtifactCoordinate> reachable = new LinkedHashSet<>();
    final TierRootResolution resolution = new TierRootResolution(operation);
    final Set<String> duplicates =
        projections.stream()
            .flatMap(projection -> projection.ownersByClass().entrySet().stream())
            .filter(entry -> entry.getValue().size() > 1)
            .map(Map.Entry::getKey)
            .collect(java.util.stream.Collectors.toSet());
    resolution.addCommonRoots(duplicates, projections, candidates, roots, reachable);
    resolution.addCommonRoots(
        TrimRootPlanner.commonRoots(operation.request()),
        projections,
        candidates,
        roots,
        reachable);
    resolution.addRequestedRoots(requested, projections, candidates, roots);
    resolution.addDynamicRoots(
        inventory.passThrough().retainedLibraries(),
        projections,
        candidates,
        roots,
        reachable,
        platformNames);
    addRequiredTargetRoots(inventory.multiReleaseCandidates(), roots);
    return new RootPlan(snapshots, candidates, roots, reachable);
  }

  private Set<String> platformClassNames(final Iterable<ClassPool> classTables) {
    final Set<String> names = new HashSet<>();
    for (final ClassPool jdkClassTable : classTables) {
      jdkClassTable.classNames().forEachRemaining(name -> names.add(name.replace('/', '.')));
    }
    return names;
  }

  private void validateStrictRoots(
      final List<TierContext> projections, final Set<String> platformNames) throws IOException {
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
          || platformNames.contains(root)) {
        continue;
      }
      if (projections.stream().noneMatch(context -> context.ownerOf(root) != null)) {
        throw new IOException("Required class root has no analyzed tier owner: " + root);
      }
    }
  }

  private List<ElisionAnalysisModel.ArtifactSnapshot> findCandidateSnapshots(
      final TrimPassThroughPlan passThrough,
      final List<TierContext> projections,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> multiRelease) {
    return passThrough.retained().stream()
        .filter(snapshot -> !operation.forcedUnchanged().contains(snapshot.coordinate()))
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
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots,
      Set<ArtifactCoordinate> reachableArtifacts) {}
}
