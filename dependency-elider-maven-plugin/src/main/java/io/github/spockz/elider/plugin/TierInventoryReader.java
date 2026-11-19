/* WHY: Binds source archive inventories and MRJAR target requirements before
 * release projections are built. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.MultiReleaseClassInventory;
import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.trimmer.JdkApiClassTableReader;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import proguard.classfile.ClassPool;

/** Reads archive ownership and MRJAR target requirements. */
@SuppressWarnings("PMD.CouplingBetweenObjects")
final class TierInventoryReader {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierInventoryReader(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ static PreparedInventory prepare(
      final MultiReleaseTrimContext operation, final TrimPassThroughPlan passThrough)
      throws IOException {
    final TierInventoryReader reader = new TierInventoryReader(operation);
    Inventory inventory = reader.readInventory(passThrough);
    final JdkClassTablePlan classTables = reader.readJdkClassTables(inventory.tiers());
    inventory = inventory.withPlatformSnapshots(classTables.snapshots());
    final List<TierContext> projections =
        new TierArchiveProjector(operation).projectInventory(inventory, classTables);
    return new PreparedInventory(inventory, classTables, projections);
  }

  /* package */ JdkClassTablePlan readJdkClassTables(final List<Integer> tiers) throws IOException {
    final JdkPlatformContext.PlatformSnapshot snapshot =
        MavenPlatformContextHolder.forOperation(operation.request().session()).snapshot();
    final JdkApiClassTableReader reader = new JdkApiClassTableReader();
    final ClassPool frozenTable = reader.readFrozen(snapshot);
    final Map<Integer, ClassPool> tablesByRelease =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    for (final int tier : tiers) {
      tablesByRelease.put(tier, frozenTable);
    }
    return new JdkClassTablePlan(List.of(snapshot), Map.copyOf(tablesByRelease));
  }

  /* package */ Inventory readInventory(final TrimPassThroughPlan passThrough) throws IOException {
    final List<ElisionAnalysisModel.ArtifactSnapshot> inventory =
        operation.request().candidates().stream()
            .filter(
                snapshot -> MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type()))
            .toList();
    TrimRootPlanner.validateAnalysisInventory(inventory);
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
    final Set<Path> projectedSources = new TreeSet<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory) {
      final Path source = snapshot.filePath().toAbsolutePath().normalize();
      final MultiReleaseClassInventory.Snapshot classInventory =
          MultiReleaseClassInventory.inspect(source);
      classesBySourcePath.put(source, classInventory.logicalClassNames());
      if (classInventory.hasUnsupportedVersionedClasses()
          || classInventory.hasRootModuleDescriptor()) {
        projectedSources.add(source);
      }
      if (!classInventory.hasUnsupportedVersionedClasses()) {
        continue;
      }
      addAnalyzedTiers(classInventory, tiers);
      addMultiReleaseCandidate(
          snapshot, source, classInventory, passThrough, projectionDirectory, multiRelease);
    }
    return new Inventory(
        inventory,
        passThrough,
        projectionDirectory,
        Map.copyOf(classesBySourcePath),
        Set.copyOf(projectedSources),
        Map.copyOf(multiRelease),
        tiers.stream().sorted().toList());
  }

  private void addAnalyzedTiers(
      final MultiReleaseClassInventory.Snapshot classInventory, final Set<Integer> tiers) {
    for (final int release : classInventory.versionedClassReleases()) {
      if (release > operation.targetRelease() && release <= operation.runtimeRelease()) {
        tiers.add(release);
      }
    }
  }

  private void addMultiReleaseCandidate(
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Path source,
      final MultiReleaseClassInventory.Snapshot classInventory,
      final TrimPassThroughPlan passThrough,
      final Path projectionDirectory,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> candidates)
      throws IOException {
    if (!passThrough.retained().contains(snapshot) || classInventory.hasRootModuleDescriptor()) {
      return;
    }
    final MultiReleaseLibraryProjection.TargetProjection targetProjection =
        MultiReleaseLibraryProjection.inspectTargetProjection(
            source, snapshot.coordinate(), projectionDirectory, operation.targetRelease());
    candidates.put(
        snapshot,
        new MultiReleaseCandidateInfo(
            targetProjection.requiredTargetRoots(),
            classInventory.classNamesAboveRelease(operation.targetRelease()),
            targetProjection.projectionPath(),
            targetProjection.targetClasses(),
            targetProjection.sourceData()));
  }

  /* package */ record Inventory(
      List<ElisionAnalysisModel.ArtifactSnapshot> snapshots,
      TrimPassThroughPlan passThrough,
      Path projectionDirectory,
      Map<Path, Set<String>> classesBySourcePath,
      Set<Path> projectedSources,
      Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> multiReleaseCandidates,
      List<Integer> tiers,
      List<JdkPlatformContext.PlatformSnapshot> platformSnapshots) {
    /* package */ Inventory(
        final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots,
        final TrimPassThroughPlan passThrough,
        final Path projectionDirectory,
        final Map<Path, Set<String>> classesBySourcePath,
        final Set<Path> projectedSources,
        final Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo>
            multiReleaseCandidates,
        final List<Integer> tiers) {
      this(
          List.copyOf(snapshots),
          passThrough,
          projectionDirectory,
          Map.copyOf(classesBySourcePath),
          Set.copyOf(projectedSources),
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
          projectedSources,
          multiReleaseCandidates,
          tiers,
          List.copyOf(snapshots));
    }
  }

  /* package */ record MultiReleaseCandidateInfo(
      Set<String> requiredTargetRoots,
      Set<String> versionedClasses,
      Path targetProjection,
      Set<String> targetClasses,
      io.github.spockz.elider.trimmer.MultiReleaseArchivePlan.SourceData sourceData) {
    /* package */ MultiReleaseCandidateInfo {
      requiredTargetRoots = Set.copyOf(requiredTargetRoots);
      versionedClasses = Set.copyOf(versionedClasses);
      targetClasses = Set.copyOf(targetClasses);
    }

    /* package */ MultiReleaseCandidateInfo(
        final Set<String> requiredTargetRoots, final Set<String> versionedClasses) {
      this(requiredTargetRoots, versionedClasses, null, Set.of(), null);
    }
  }

  /* package */ record JdkClassTablePlan(
      List<JdkPlatformContext.PlatformSnapshot> snapshots, Map<Integer, ClassPool> byRelease) {}

  /* package */ record PreparedInventory(
      Inventory inventory, JdkClassTablePlan classTables, List<TierContext> projections) {}
}
