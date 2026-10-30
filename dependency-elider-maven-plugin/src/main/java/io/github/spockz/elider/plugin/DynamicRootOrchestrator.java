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
    final Set<String> classNames = new HashSet<>();
    final Set<ArtifactCoordinate> declaringArtifacts = new HashSet<>();
    final Map<Path, DependencyDynamicRoots.RootScan> scansByPath =
        LinkedHashMap.newLinkedHashMap(candidates.size());
    final Map<ArtifactCoordinate, Set<String>> unprovenRootsByCoordinate =
        LinkedHashMap.newLinkedHashMap(candidates.size());
    for (final ArtifactFileRef candidate : candidates) {
      DependencyDynamicRoots.RootScan scan = scansByPath.get(candidate.filePath());
      if (scan == null) {
        scan = scanArchive(candidate, scanner);
        scansByPath.put(candidate.filePath(), scan);
      }
      final DependencyDynamicRoots.EffectiveRoots effective =
          scan.effectiveRoots(provenServiceInterfaces, conservativeServiceLoaderRoots);
      classNames.addAll(effective.roots());
      if (effective.declaresRoots() || scan.requiresPassThrough()) {
        declaringArtifacts.add(candidate.coordinate());
      }
      warnPassThrough(candidate, scan);
      if (!effective.unprovenConservativeRoots().isEmpty()) {
        unprovenRootsByCoordinate.put(
            candidate.coordinate(), effective.unprovenConservativeRoots());
      }
    }
    return new DynamicRootInputs(
        classNames,
        declaringArtifacts,
        scansByPath,
        unprovenRootsByCoordinate,
        provenServiceInterfaces);
  }

  private static DependencyDynamicRoots.RootScan scanArchive(
      final ArtifactFileRef candidate, final DynamicRootScanner scanner) throws IOException {
    try {
      return scanner.scan(candidate.filePath());
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

  private static void warnPassThrough(
      final ArtifactFileRef candidate, final DependencyDynamicRoots.RootScan scan) {
    if (!scan.requiresPassThrough()) {
      return;
    }
    for (final NativeImageDynamicRoots.UnsupportedArgument argument :
        scan.unsupportedNativeImageArgs()) {
      System.getLogger(MavenElisionService.class.getName())
          .log(
              System.Logger.Level.WARNING,
              "Retaining native-image artifact "
                  + candidate.coordinate()
                  + " at "
                  + candidate.filePath()
                  + " without trimming: "
                  + argument.name()
                  + " in "
                  + argument.entry()
                  + " (full argument: '"
                  + argument.fullArgument()
                  + "')");
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
