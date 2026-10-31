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
import java.util.concurrent.ConcurrentHashMap;

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
    final Set<String> routedRoots = new HashSet<>();
    for (final ArtifactFileRef candidate : candidates) {
      final DependencyDynamicRoots.RootScan scan = scansByPath.get(candidate.filePath());
      final DependencyDynamicRoots.EffectiveRoots effective =
          scan.effectiveRoots(
              provenServiceInterfaces, conservativeServiceLoaderRoots, servicePolicy);
      routedRoots.addAll(featureRoots(scan, servicePolicy));
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
        scansByPath,
        unprovenRootsByCoordinate,
        provenServiceInterfaces,
        NativeImageConsumedInput.ordered(consumedInputs));
  }

  private static Set<String> featureRoots(
      final DependencyDynamicRoots.RootScan scan,
      final NativeImageServiceLoaderPolicy.Selection selection) {
    if (!selection.enabled()) {
      return Set.of();
    }
    final Set<String> roots = new HashSet<>();
    for (final DependencyDynamicRoots.ServiceDescriptor descriptor : scan.serviceDescriptors()) {
      if (selection.excludedServices().contains(descriptor.serviceInterface())) {
        continue;
      }
      roots.add(descriptor.serviceInterface());
      descriptor.providers().stream()
          .filter(provider -> !selection.excludedProviders().contains(provider))
          .forEach(roots::add);
    }
    return roots;
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
      owned.clear();
      owned.addAll(roots);
      owned.retainAll(context.logicalClasses(java.util.Optional.of(candidate.filePath())));
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
    final Map<String, Set<ArtifactCoordinate>> ownersByClass = new ConcurrentHashMap<>();
    index
        .classesByArtifact()
        .forEach(
            (artifact, classes) ->
                classes.forEach(
                    className ->
                        ownersByClass
                            .computeIfAbsent(
                                className.replace('/', '.'),
                                ignored -> ConcurrentHashMap.newKeySet())
                            .add(artifact.coordinate())));
    final Set<ArtifactCoordinate> result = new HashSet<>();
    boolean unresolvedOwner = false;
    for (final String rawRoot : dynamicRoots.classNames()) {
      final Set<ArtifactCoordinate> owners =
          ownersByClass.getOrDefault(rawRoot.replace('/', '.'), Set.of());
      if (owners.isEmpty()) {
        unresolvedOwner = true;
      } else {
        result.addAll(owners);
      }
    }
    if (unresolvedOwner) {
      inventory.stream().map(ArtifactFileRef::coordinate).forEach(result::add);
    }
    return Set.copyOf(result);
  }
}
