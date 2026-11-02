// WHY: Aggregates dependency dynamic roots once per archive while retaining
// artifact policy context.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootInputs;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootScanner;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Aggregates dependency roots once per archive with artifact policy context. */
final class DynamicRootOrchestrator {
  private DynamicRootOrchestrator() {}

  /* package */ static DynamicRootInputs dynamicRoots(final List<ArtifactFileRef> candidates)
      throws IOException {
    return dynamicRoots(candidates, DependencyDynamicRoots::scan, Set.of(), true);
  }

  /* package */ static DynamicRootInputs dynamicRoots(
      final List<ArtifactFileRef> candidates, final DynamicRootScanner scanner) throws IOException {
    return dynamicRoots(candidates, scanner, Set.of(), true);
  }

  /* package */ static DynamicRootInputs dynamicRoots(
      final List<ArtifactFileRef> candidates,
      final DynamicRootScanner scanner,
      final Set<String> provenServiceInterfaces,
      final boolean conservativeServiceLoaderRoots)
      throws IOException {
    return dynamicRoots(
        candidates,
        scanner,
        NativeImageScanContext.create(candidates, null),
        provenServiceInterfaces,
        conservativeServiceLoaderRoots);
  }

  /* package */ static DynamicRootInputs dynamicRoots(
      final List<ArtifactFileRef> candidates,
      final DynamicRootScanner scanner,
      final NativeImageScanContext context,
      final Set<String> provenServiceInterfaces,
      final boolean conservativeServiceLoaderRoots)
      throws IOException {
    final Set<String> classNames = new HashSet<>();
    final Set<ArtifactCoordinate> declaringArtifacts = new HashSet<>();
    final Map<Path, DependencyDynamicRoots.RootScan> scansByPath =
        LinkedHashMap.newLinkedHashMap(candidates.size());
    final Map<ArtifactCoordinate, Set<String>> unprovenRootsByCoordinate =
        LinkedHashMap.newLinkedHashMap(candidates.size());
    final Set<Path> resourceProviderPaths = new HashSet<>();
    final List<NativeImagePolicyRoots.ResourcePatternSelection> resourcePatterns =
        new java.util.ArrayList<>();
    for (final ArtifactFileRef candidate : candidates) {
      DependencyDynamicRoots.RootScan scan = scansByPath.get(candidate.filePath());
      if (scan == null) {
        scan = scanArchive(candidate, scanner, context);
        scansByPath.put(candidate.filePath(), scan);
      }
      resourceProviderPaths.addAll(scan.resourceProviders());
      resourcePatterns.add(scan.resourcePatterns());
      if (scan.requiresArtifactRetention()) {
        declaringArtifacts.add(candidate.coordinate());
      }
    }
    final NativeImageServiceLoaderPolicy.Selection servicePolicy =
        NativeImageServiceLoaderPolicy.merge(
            scansByPath.values().stream()
                .map(DependencyDynamicRoots.RootScan::serviceLoaderPolicy)
                .toList());
    final Map<Path, DependencyDynamicRoots.EffectiveRoots> effectiveRootsByPath =
        scansByPath.entrySet().stream()
            .collect(
                java.util.stream.Collectors.toUnmodifiableMap(
                    Map.Entry::getKey,
                    entry ->
                        entry
                            .getValue()
                            .effectiveRoots(
                                provenServiceInterfaces,
                                conservativeServiceLoaderRoots,
                                servicePolicy)));
    final Set<String> routedRoots = new HashSet<>();
    for (final ArtifactFileRef candidate : candidates) {
      final DependencyDynamicRoots.EffectiveRoots effective =
          effectiveRootsByPath.get(candidate.filePath());
      routedRoots.addAll(effective.featureRoots());
      classNames.addAll(effective.roots());
      if (effective.declaresRoots()) {
        declaringArtifacts.add(candidate.coordinate());
      }
      if (!effective.unprovenConservativeRoots().isEmpty()) {
        unprovenRootsByCoordinate.put(
            candidate.coordinate(), effective.unprovenConservativeRoots());
      }
    }
    final Set<String> patternRoots = new HashSet<>();
    NativeImagePolicyRoots.applyResourcePatterns(
        resourcePatterns, context, patternRoots, resourceProviderPaths);
    final DynamicRootProvenance provenance =
        DynamicRootProvenance.collect(
            candidates, scansByPath, effectiveRootsByPath, resourcePatterns, context);
    classNames.addAll(patternRoots);
    routedRoots.addAll(patternRoots);
    addOwnerRoots(routedRoots, candidates, context, scansByPath);
    final Set<ArtifactCoordinate> resourceProviders = new HashSet<>();
    for (final ArtifactFileRef candidate : candidates) {
      if (resourceProviderPaths.contains(candidate.filePath().toRealPath())) {
        resourceProviders.add(candidate.coordinate());
      }
    }
    final Set<NativeImageConsumedInput> consumedInputs = new HashSet<>();
    scansByPath.values().forEach(scan -> consumedInputs.addAll(scan.consumedInputs()));
    return new DynamicRootInputs(
        classNames,
        declaringArtifacts,
        resourceProviders,
        provenance.classRootsByDeclaringArtifact(),
        provenance.resourceProvidersByDeclaringArtifact(),
        scansByPath,
        unprovenRootsByCoordinate,
        provenServiceInterfaces,
        NativeImageConsumedInput.ordered(consumedInputs));
  }

  private static DependencyDynamicRoots.RootScan scanArchive(
      final ArtifactFileRef candidate,
      final DynamicRootScanner scanner,
      final NativeImageScanContext context)
      throws IOException {
    try {
      return scanner.scan(candidate.filePath(), context);
    } catch (final IOException exception) {
      throw new IOException(
          "Cannot scan dependency artifact "
              + candidate.coordinate()
              + " at "
              + candidate.filePath()
              + ": "
              + exception.getMessage(),
          exception);
    }
  }

  private static void addOwnerRoots(
      final Set<String> roots,
      final List<ArtifactFileRef> candidates,
      final NativeImageScanContext context,
      final Map<Path, DependencyDynamicRoots.RootScan> scansByPath)
      throws IOException {
    if (roots.isEmpty()) {
      return;
    }
    final Set<String> owned = new HashSet<>();
    for (final ArtifactFileRef candidate : candidates) {
      final Set<String> classes =
          context.logicalClasses(java.util.Optional.of(candidate.filePath()));
      final boolean rootsAreSmaller = roots.size() <= classes.size();
      final Set<String> smaller = rootsAreSmaller ? roots : classes;
      final Set<String> larger = rootsAreSmaller ? classes : roots;
      owned.clear();
      for (final String className : smaller) {
        if (larger.contains(className)) {
          owned.add(className);
        }
      }
      if (!owned.isEmpty()) {
        scansByPath.computeIfPresent(
            candidate.filePath(), (ignored, scan) -> scan.withAdditionalClassRoots(owned));
      }
    }
  }

  /* package */ static Set<String> requiredClassesForTrimming(
      final Set<String> sourceClasses,
      final Set<String> dynamicClasses,
      final List<String> explicitRoots,
      final ArtifactClassIndex index,
      final boolean trimJars)
      throws IOException {
    final Set<String> required = new HashSet<>(sourceClasses);
    required.addAll(dynamicClasses);
    if (!trimJars) {
      return required;
    }
    final Set<String> indexedNames = new HashSet<>();
    index.classesByArtifact().values().forEach(indexedNames::addAll);
    if (explicitRoots != null) {
      for (final String root : explicitRoots) {
        if (root == null || root.isBlank()) {
          throw new IOException("elide.trimRoots must not contain blank class names");
        }
        final String normalized = TraceData.normalizeToDot(root.trim());
        if (!indexedNames.contains(normalized)) {
          throw new IOException(
              "elide.trimRoots class is not present in a dependency JAR: " + root);
        }
        required.add(normalized);
      }
    }
    return Set.copyOf(required);
  }

  /* package */ static Set<ArtifactCoordinate> dynamicRootArtifactOwners(
      final DynamicRootInputs dynamicRoots,
      final ArtifactClassIndex index,
      final List<ArtifactFileRef> inventory) {
    final Set<String> roots =
        dynamicRoots.classNames().stream()
            .map(className -> className.replace('/', '.'))
            .collect(java.util.stream.Collectors.toSet());
    if (roots.isEmpty()) {
      return Set.of();
    }
    final Set<ArtifactCoordinate> result = new HashSet<>();
    final Set<String> unresolvedRoots = new HashSet<>(roots);
    for (final Map.Entry<ArtifactFileRef, Set<String>> artifact :
        index.classesByArtifact().entrySet()) {
      boolean ownsRoot = false;
      for (final String className : artifact.getValue()) {
        final String normalizedName = className.replace('/', '.');
        if (roots.contains(normalizedName)) {
          ownsRoot = true;
          unresolvedRoots.remove(normalizedName);
        }
      }
      if (ownsRoot) {
        result.add(artifact.getKey().coordinate());
      }
    }
    if (!unresolvedRoots.isEmpty()) {
      inventory.stream().map(ArtifactFileRef::coordinate).forEach(result::add);
    }
    return Set.copyOf(result);
  }
}
