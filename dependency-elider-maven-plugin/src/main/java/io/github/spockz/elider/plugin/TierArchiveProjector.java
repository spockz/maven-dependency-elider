/* WHY: Builds release-specific class ownership so closure follows
 * implementation bodies available at each tier. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TierInventoryReader.Inventory;
import io.github.spockz.elider.plugin.TierInventoryReader.MultiReleaseCandidateInfo;
import io.github.spockz.elider.plugin.TierPlatformReader.PlatformPlan;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import proguard.classfile.ClassPool;

/** Builds classpath projections and class ownership for each runtime tier. */
final class TierArchiveProjector {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierArchiveProjector(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ List<TierContext> projectInventory(
      final Inventory inventory, final PlatformPlan platforms) throws IOException {
    final List<TierContext> contexts = new ArrayList<>();
    for (final int tier : inventory.tiers()) {
      contexts.add(projectTier(inventory, platforms.byRelease().get(tier), tier));
    }
    return List.copyOf(contexts);
  }

  private TierContext projectTier(
      final Inventory inventory, final ClassPool platform, final int release) throws IOException {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Path> paths =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> classes =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    final Map<String, ElisionAnalysisModel.ArtifactSnapshot> owners =
        HashMap.newHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory.snapshots()) {
      if (!MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope())) {
        continue;
      }
      addTierArtifact(inventory.projectionDirectory(), release, snapshot, paths, classes);
      assignTierOwners(classes.get(snapshot), snapshot, owners, release);
    }
    return new TierContext(
        release,
        operation.targetRelease(),
        inventory.multiReleaseCandidates(),
        paths,
        classes,
        owners,
        Map.of(),
        Map.of(),
        platform);
  }

  private void addTierArtifact(
      final Path projectionDirectory,
      final int release,
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Path> paths,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> classes)
      throws IOException {
    final Path source = snapshot.filePath().toAbsolutePath().normalize();
    final boolean needsProjection =
        MultiReleaseClassInventory.hasUnsupportedVersionedClasses(source)
            || MultiReleaseLibraryProjection.hasRootModuleDescriptor(source);
    final Path analysisPath =
        needsProjection
            ? MultiReleaseLibraryProjection.create(
                source, snapshot.coordinate(), projectionDirectory, release)
            : source;
    paths.put(snapshot, analysisPath);
    classes.put(snapshot, TrimPaths.classNames(analysisPath));
  }

  private static void assignTierOwners(
      final Set<String> names,
      final ElisionAnalysisModel.ArtifactSnapshot snapshot,
      final Map<String, ElisionAnalysisModel.ArtifactSnapshot> owners,
      final int release)
      throws IOException {
    for (final String name : names) {
      final ElisionAnalysisModel.ArtifactSnapshot previous = owners.putIfAbsent(name, snapshot);
      if (previous != null && !previous.equals(snapshot)) {
        throw new IOException("Duplicate class owner in tier " + release + ": " + name);
      }
    }
  }

  /* package */ record TierContext(
      int tierRelease,
      int targetCompilerRelease,
      Map<ElisionAnalysisModel.ArtifactSnapshot, MultiReleaseCandidateInfo> multiReleaseCandidates,
      Map<ElisionAnalysisModel.ArtifactSnapshot, Path> paths,
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> classes,
      Map<String, ElisionAnalysisModel.ArtifactSnapshot> ownerByClass,
      Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          candidatePrepared,
      Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          programPrepared,
      ClassPool platformPool) {
    /* package */ TierContext {
      multiReleaseCandidates = Map.copyOf(multiReleaseCandidates);
      paths = Map.copyOf(paths);
      classes = Map.copyOf(classes);
      ownerByClass = Map.copyOf(ownerByClass);
      candidatePrepared = Map.copyOf(candidatePrepared);
      programPrepared = Map.copyOf(programPrepared);
    }

    /* package */ TierContext withPrepared(
        final Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
            candidates,
        final Map<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
            programs) {
      return new TierContext(
          tierRelease,
          targetCompilerRelease,
          multiReleaseCandidates,
          paths,
          classes,
          ownerByClass,
          candidates,
          programs,
          platformPool);
    }

    /* package */ int release() {
      return tierRelease;
    }

    /* package */ int targetRelease() {
      return targetCompilerRelease;
    }

    /* package */ Path pathFor(final ElisionAnalysisModel.ArtifactSnapshot snapshot) {
      return paths.get(snapshot);
    }

    /* package */ Set<String> classesOf(final ElisionAnalysisModel.ArtifactSnapshot snapshot) {
      return classes.getOrDefault(snapshot, Set.of());
    }

    /* package */ ElisionAnalysisModel.ArtifactSnapshot ownerOf(final String name) {
      return ownerByClass.get(name);
    }

    /* package */ ClassPool platform() {
      return platformPool;
    }

    /* package */ List<
            Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
        candidateEntries() {
      return TierAnalysisViews.orderedEntries(candidatePrepared);
    }

    /* package */ List<
            Map.Entry<ElisionAnalysisModel.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
        programEntries() {
      return TierAnalysisViews.orderedEntries(programPrepared);
    }

    /* package */ MultiReleaseCandidateInfo multiReleaseInfo(
        final ElisionAnalysisModel.ArtifactSnapshot snapshot) {
      return multiReleaseCandidates.get(snapshot);
    }
  }
}
