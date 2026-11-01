/* WHY: Binds source archive inventories and MRJAR target requirements before
 * release projections are built. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.JdkPlatformContext;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Reads archive ownership and MRJAR target requirements. */
final class TierInventoryReader {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierInventoryReader(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ Inventory readInventory() throws IOException {
    final List<ElisionAnalysisModel.ArtifactSnapshot> inventory =
        operation.request().candidates().stream()
            .filter(
                snapshot -> MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type()))
            .toList();
    TrimRootPlanner.validateAnalysisInventory(inventory);
    final TrimPassThroughPlan passThrough =
        TrimPassThroughPlanner.passThroughPlan(operation.request());
    final Path projectionDirectory =
        TrimPaths.analysisLibraryDirectory(
            operation.request().project(), operation.request().environment());
    final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> multiRelease =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    final Set<Integer> tiers = new TreeSet<>();
    tiers.add(operation.targetRelease());
    tiers.add(operation.runtimeRelease());
    final Map<Path, Set<String>> classesBySourcePath =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory) {
      final Path source = snapshot.filePath().toAbsolutePath().normalize();
      classesBySourcePath.put(source, TrimPaths.logicalClassNames(source));
      if (!MultiReleaseClassInventory.hasUnsupportedVersionedClasses(source)) {
        continue;
      }
      addAnalyzedTiers(source, tiers);
      addMultiReleaseCandidate(snapshot, source, passThrough, projectionDirectory, multiRelease);
    }
    return new Inventory(
        inventory,
        passThrough,
        projectionDirectory,
        Map.copyOf(classesBySourcePath),
        Map.copyOf(multiRelease),
        tiers.stream().sorted().toList());
  }

  private void addAnalyzedTiers(final Path source, final Set<Integer> tiers) throws IOException {
    for (final int release : MultiReleaseClassInventory.versionedClassReleases(source)) {
      if (release > operation.targetRelease() && release <= operation.runtimeRelease()) {
        tiers.add(release);
      }
    }
  }

  private void addMultiReleaseCandidate(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Path source,
      final TrimPassThroughPlan passThrough,
      final Path projectionDirectory,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> candidates)
      throws IOException {
    if (!passThrough.retained().contains(snapshot)
        || MultiReleaseLibraryProjection.hasRootModuleDescriptor(source)) {
      return;
    }
    final Path targetProjection =
        MultiReleaseLibraryProjection.create(
            source, snapshot.coordinate(), projectionDirectory, operation.targetRelease());
    final Set<String> targetClasses = TrimPaths.classNames(targetProjection);
    final MultiReleaseArchivePlan.PluginView view =
        MultiReleaseArchivePlan.create(source, operation.targetRelease(), Set.of(), Set.of())
            .pluginView();
    final Set<String> viewClasses = dottedNames(view.targetPresentClasses());
    if (!viewClasses.equals(targetClasses)) {
      throw new IOException(
          "MRJAR target projection and archive plan disagree for " + snapshot.coordinate());
    }
    candidates.put(
        snapshot,
        new MultiReleaseCandidateInfo(
            dottedNames(view.requiredRootClasses()),
            MultiReleaseClassInventory.classNamesAboveRelease(source, operation.targetRelease())));
  }

  private static Set<String> dottedNames(final Set<String> names) {
    return names.stream()
        .map(name -> name.replace('/', '.'))
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
  }

  /* package */ record Inventory(
      List<ElisionAnalysisModel.ArtifactSnapshot> snapshots,
      TrimPassThroughPlan passThrough,
      Path projectionDirectory,
      Map<Path, Set<String>> classesBySourcePath,
      Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> multiReleaseCandidates,
      List<Integer> tiers,
      List<JdkPlatformContext.PlatformSnapshot> platformSnapshots) {
    /* package */ Inventory(
        final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots,
        final TrimPassThroughPlan passThrough,
        final Path projectionDirectory,
        final Map<Path, Set<String>> classesBySourcePath,
        final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo>
            multiReleaseCandidates,
        final List<Integer> tiers) {
      this(
          List.copyOf(snapshots),
          passThrough,
          projectionDirectory,
          Map.copyOf(classesBySourcePath),
          Map.copyOf(multiReleaseCandidates),
          List.copyOf(tiers),
          List.of());
    }

    /* package */ Inventory withPlatformSnapshots(
        final List<JdkPlatformContext.PlatformSnapshot> snapshots) {
      return new Inventory(
          this.snapshots,
          passThrough,
          projectionDirectory,
          classesBySourcePath,
          multiReleaseCandidates,
          tiers,
          List.copyOf(snapshots));
    }
  }

  /* package */ record MultiReleaseCandidateInfo(
      Set<String> requiredTargetRoots, Set<String> versionedClasses) {
    /* package */ MultiReleaseCandidateInfo {
      requiredTargetRoots = Set.copyOf(requiredTargetRoots);
      versionedClasses = Set.copyOf(versionedClasses);
    }
  }
}
