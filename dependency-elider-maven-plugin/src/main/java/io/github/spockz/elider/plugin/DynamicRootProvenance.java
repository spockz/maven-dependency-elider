// WHY: Retains the declaring archive for dynamic roots so Analyze can distinguish self-origin
// metadata from obligations declared by another retained dependency.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Roots and providers attributed to their declaring artifact. */
@SuppressWarnings({"PMD.AvoidInstantiatingObjectsInLoops", "PMD.UseConcurrentHashMap"})
/* package */ record DynamicRootProvenance(
    Map<ArtifactCoordinate, Set<String>> classRootsByDeclaringArtifact,
    Map<ArtifactCoordinate, Set<ArtifactCoordinate>> resourceProvidersByDeclaringArtifact) {
  /* package */ static DynamicRootProvenance collect(
      final List<ArtifactFileRef> candidates,
      final Map<Path, DependencyDynamicRoots.RootScan> scansByPath,
      final Map<Path, DependencyDynamicRoots.EffectiveRoots> effectiveRootsByPath,
      final List<NativeImagePolicyRoots.ResourcePatternSelection> resourcePatterns,
      final NativeImageScanContext context)
      throws IOException {
    final Map<ArtifactCoordinate, Set<String>> classRoots = new LinkedHashMap<>();
    final Map<ArtifactCoordinate, Set<Path>> providerPaths = new LinkedHashMap<>();
    for (final ArtifactFileRef candidate : candidates) {
      addAll(
          classRoots,
          candidate.coordinate(),
          effectiveRootsByPath.get(candidate.filePath()).roots());
      addAll(
          providerPaths,
          candidate.coordinate(),
          scansByPath.get(candidate.filePath()).resourceProviders());
    }
    attributeResourcePatterns(
        candidates, scansByPath, resourcePatterns, context, classRoots, providerPaths);
    return new DynamicRootProvenance(classRoots, providerCoordinates(providerPaths, candidates));
  }

  private static void attributeResourcePatterns(
      final List<ArtifactFileRef> candidates,
      final Map<Path, DependencyDynamicRoots.RootScan> scansByPath,
      final List<NativeImagePolicyRoots.ResourcePatternSelection> resourcePatterns,
      final NativeImageScanContext context,
      final Map<ArtifactCoordinate, Set<String>> classRoots,
      final Map<ArtifactCoordinate, Set<Path>> providerPaths)
      throws IOException {
    final List<NativeImageResourcePatternMatcher.Selector> allExcludes =
        resourcePatterns.stream().flatMap(selection -> selection.excludes().stream()).toList();
    for (final ArtifactFileRef candidate : candidates) {
      final NativeImagePolicyRoots.ResourcePatternSelection selection =
          scansByPath.get(candidate.filePath()).resourcePatterns();
      if (selection.includes().isEmpty() && selection.bundles().isEmpty()) {
        continue;
      }
      final Set<String> sourceRoots = new HashSet<>();
      final Set<Path> sourceProviders = new HashSet<>();
      NativeImagePolicyRoots.applyResourcePatterns(
          List.of(
              new NativeImagePolicyRoots.ResourcePatternSelection(
                  selection.includes(), allExcludes, selection.bundles())),
          context,
          sourceRoots,
          sourceProviders);
      addAll(classRoots, candidate.coordinate(), sourceRoots);
      addAll(providerPaths, candidate.coordinate(), sourceProviders);
    }
  }

  private static Map<ArtifactCoordinate, Set<ArtifactCoordinate>> providerCoordinates(
      final Map<ArtifactCoordinate, Set<Path>> providerPaths,
      final List<ArtifactFileRef> candidates)
      throws IOException {
    final Map<Path, Set<ArtifactCoordinate>> coordinatesByPath = new LinkedHashMap<>();
    for (final ArtifactFileRef candidate : candidates) {
      addAll(coordinatesByPath, candidate.filePath().toRealPath(), Set.of(candidate.coordinate()));
    }
    final Map<ArtifactCoordinate, Set<ArtifactCoordinate>> providers = new LinkedHashMap<>();
    for (final Map.Entry<ArtifactCoordinate, Set<Path>> source : providerPaths.entrySet()) {
      final Set<ArtifactCoordinate> selected = new HashSet<>();
      for (final Path path : source.getValue()) {
        selected.addAll(coordinatesByPath.getOrDefault(path.toRealPath(), Set.of()));
      }
      providers.put(source.getKey(), selected);
    }
    return providers;
  }

  private static <K, V> void addAll(
      final Map<K, Set<V>> destination, final K key, final Set<V> values) {
    destination.computeIfAbsent(key, ignored -> new HashSet<>()).addAll(values);
  }
}
