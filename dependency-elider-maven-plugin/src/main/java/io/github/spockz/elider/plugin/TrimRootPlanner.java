/* WHY: Binds roots to verified archive owners so stale metadata cannot
 * retain or trim an unrelated dependency. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Binds roots to verified owners before they can retain or trim an archive. */
final class TrimRootPlanner {
  private TrimRootPlanner() {}

  /* package */ record CommonRootOwners(
      Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> byArtifact,
      Set<ArtifactCoordinate> droppedArtifacts) {}

  /* package */ static Map<TrimArtifactRootKey, Set<String>> immutableRootMap(
      final Map<TrimArtifactRootKey, Set<String>> roots) {
    final Map<TrimArtifactRootKey, Set<String>> result = TrimCollections.orderedMap();
    roots.entrySet().stream()
        .sorted(
            Comparator.comparing(
                    (Map.Entry<TrimArtifactRootKey, Set<String>> entry) ->
                        entry.getKey().coordinate())
                .thenComparing(entry -> entry.getKey().path()))
        .forEach(
            entry ->
                result.put(
                    entry.getKey(),
                    java.util.Collections.unmodifiableSet(new TreeSet<>(entry.getValue()))));
    return java.util.Collections.unmodifiableMap(result);
  }

  /* package */ static Map<TrimArtifactRootKey, Set<String>> artifactRootKeys(
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
      final Map<ArtifactCoordinate, Set<String>> rootsByCoordinate)
      throws IOException {
    final Map<TrimArtifactRootKey, Set<String>> result = TrimCollections.orderedMap();
    for (final Map.Entry<ArtifactCoordinate, Set<String>> entry : rootsByCoordinate.entrySet()) {
      result.put(RootArchiveBinding.key(inventory, entry.getKey()), entry.getValue());
    }
    return java.util.Collections.unmodifiableMap(result);
  }

  /* package */ static void validateAnalysisInventory(
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory) throws IOException {
    final Set<ArtifactCoordinate> coordinates = new HashSet<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : inventory) {
      if (!coordinates.add(snapshot.coordinate())) {
        throw new IOException(
            "Duplicate JAR identity in analysis inventory: " + snapshot.coordinate());
      }
      if (snapshot.filePath() == null || !Files.isRegularFile(snapshot.filePath())) {
        throw new IOException("Incomplete JAR analysis inventory: " + snapshot.coordinate());
      }
    }
  }

  /* package */ static Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>>
      validateDiscoveredRoots(
          final Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
          final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
          final Map<Path, Set<String>> classesByPath)
          throws IOException {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> result =
        TrimCollections.orderedMap();
    for (final Map.Entry<TrimArtifactRootKey, Set<String>> entry : discoveredRoots.entrySet()) {
      final ElisionAnalysisModel.ArtifactSnapshot snapshot =
          RootArchiveBinding.validate(entry, inventory, classesByPath);
      RootArchiveBinding.rootsFor(result, snapshot).addAll(entry.getValue());
    }
    return result;
  }

  /* package */ static Set<String> commonRoots(final TrimRequest request) {
    final Set<String> roots =
        new LinkedHashSet<>(request.evidence().trace().loadedClassesDotFormat());
    roots.addAll(request.evidence().sourceRoots());
    roots.addAll(request.evidence().bytecodeRoots());
    request.policy().explicitRoots().forEach(roots::add);
    return roots;
  }

  /* package */ static CommonRootOwners commonRootOwners(
      final Set<String> roots,
      final Map<String, ElisionAnalysisModel.ArtifactSnapshot> ownerByClass,
      final TrimRequest request,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> classesByArtifact,
      final Set<String> platformClasses)
      throws IOException {
    final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> rootsByArtifact =
        TrimCollections.orderedMap();
    final Set<ArtifactCoordinate> droppedArtifacts = new LinkedHashSet<>();
    final Set<String> strictRoots = new HashSet<>();
    request.evidence().sourceRoots().forEach(root -> strictRoots.add(root.replace('/', '.')));
    request.evidence().bytecodeRoots().forEach(root -> strictRoots.add(root.replace('/', '.')));
    request.policy().explicitRoots().forEach(root -> strictRoots.add(root.replace('/', '.')));
    for (final String rawRoot : roots) {
      final String root = rawRoot.replace('/', '.');
      final ElisionAnalysisModel.ArtifactSnapshot owner = ownerByClass.get(root);
      if (owner == null) {
        if (request.evidence().projectOutputClasses().contains(root)
            || platformClasses.contains(root)) {
          continue;
        }
        if (strictRoots.contains(root)) {
          throw new IOException("Required class root has no recognized owner: " + root);
        }
        continue;
      }
      if (!retainedCoordinates.contains(owner.coordinate())) {
        droppedArtifacts.add(owner.coordinate());
        continue;
      }
      if (classesByArtifact.getOrDefault(owner, Set.of()).contains(root)) {
        RootArchiveBinding.rootsFor(rootsByArtifact, owner).add(root);
      }
    }
    return new CommonRootOwners(rootsByArtifact, droppedArtifacts);
  }

  /* package */ static Set<String> dynamicRoots(final TrimRequest request, final Path path)
      throws IOException {
    final DependencyDynamicRoots.RootScan scan = request.scanInputs().dynamicRootScans().get(path);
    if (scan == null) {
      throw new IOException("Missing dynamic-root scan for full inventory JAR: " + path);
    }
    final DependencyDynamicRoots.EffectiveRoots effective =
        scan.effectiveRoots(
            request.evidence().provenServiceInterfaces(),
            request.policy().conservativeServiceLoaderRoots());
    return effective.roots().stream()
        .map(name -> name.replace('/', '.'))
        .collect(java.util.stream.Collectors.toSet());
  }

  /* package */ static TrimAnalysisResult inMemoryResult(
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> analyses,
      final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots,
      final Set<ArtifactCoordinate> reachableArtifacts,
      final int analysisRuns,
      final int compilerRelease,
      final int runtimeRelease,
      final Path javaHome,
      final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots,
      final Map<ArtifactCoordinate, Set<String>> upperTierClasses) {
    final Map<ArtifactCoordinate, Set<String>> rootsByCoordinate = TrimCollections.orderedMap();
    roots.forEach((snapshot, values) -> rootsByCoordinate.put(snapshot.coordinate(), values));
    return new TrimAnalysisResult(
        analyses,
        rootsByCoordinate,
        reachableArtifacts,
        analysisRuns,
        compilerRelease,
        runtimeRelease,
        javaHome,
        platformSnapshots.stream()
            .sorted(Comparator.comparingInt(JdkPlatformContext.PlatformSnapshot::effectiveRelease))
            .map(JdkPlatformContext.PlatformSnapshot::identity)
            .toList(),
        platformSnapshots.stream()
            .map(JdkPlatformContext.PlatformSnapshot::effectiveRelease)
            .distinct()
            .sorted()
            .toList(),
        upperTierClasses);
  }

  /* package */ static Map<ArtifactCoordinate, Set<String>> immutableSetMap(
      final Map<ArtifactCoordinate, Set<String>> values) {
    final Map<ArtifactCoordinate, Set<String>> result = TrimCollections.orderedMap();
    values.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(
            entry ->
                result.put(
                    entry.getKey(),
                    java.util.Collections.unmodifiableSet(new TreeSet<>(entry.getValue()))));
    return java.util.Collections.unmodifiableMap(result);
  }

  /* package */ static Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis>
      immutableAnalysisMap(
          final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> values) {
    final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> result =
        TrimCollections.orderedMap();
    values.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(entry -> result.put(entry.getKey(), entry.getValue()));
    return java.util.Collections.unmodifiableMap(result);
  }

  /** Validates one archive binding before roots can affect an analysis candidate. */
  private static final class RootArchiveBinding {
    /** Keeps archive validation operations static. */
    private RootArchiveBinding() {
      super();
    }

    private static TrimArtifactRootKey key(
        final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
        final ArtifactCoordinate coordinate)
        throws IOException {
      final ElisionAnalysisModel.ArtifactSnapshot owner =
          inventory.stream()
              .filter(snapshot -> snapshot.coordinate().equals(coordinate))
              .filter(
                  snapshot -> MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type()))
              .findFirst()
              .orElseThrow(
                  () ->
                      new IOException("Effective roots have no inventory artifact: " + coordinate));
      final Path path = owner.filePath().toAbsolutePath().normalize();
      return new TrimArtifactRootKey(coordinate, path, ArtifactDigests.read(path).sha256());
    }

    private static ElisionAnalysisModel.ArtifactSnapshot validate(
        final Map.Entry<TrimArtifactRootKey, Set<String>> entry,
        final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
        final Map<Path, Set<String>> classesByPath)
        throws IOException {
      final TrimArtifactRootKey key = entry.getKey();
      if (!HexDigest.isLowercaseHex(key.sha256(), 64)) {
        throw new IOException("Invalid discovered-root artifact digest: " + key.coordinate());
      }
      final ElisionAnalysisModel.ArtifactSnapshot snapshot =
          inventory.stream()
              .filter(candidate -> candidate.coordinate().equals(key.coordinate()))
              .filter(
                  candidate -> candidate.filePath().toAbsolutePath().normalize().equals(key.path()))
              .findFirst()
              .orElseThrow(
                  () ->
                      new IOException(
                          "Discovered roots do not match an inventory artifact: "
                              + key.coordinate()));
      if (!ArtifactDigests.read(key.path()).sha256().equals(key.sha256())) {
        throw new IOException("Discovered-root input digest changed: " + key.coordinate());
      }
      final Set<String> classes = classesByPath.get(key.path());
      if (classes == null || !classes.containsAll(entry.getValue())) {
        throw new IOException(
            "Discovered root is not indexed in its owning JAR: " + key.coordinate());
      }
      return snapshot;
    }

    private static Set<String> rootsFor(
        final Map<ElisionAnalysisModel.ArtifactSnapshot, Set<String>> roots,
        final ElisionAnalysisModel.ArtifactSnapshot owner) {
      return roots.computeIfAbsent(owner, ignored -> new TreeSet<>());
    }
  }
}
