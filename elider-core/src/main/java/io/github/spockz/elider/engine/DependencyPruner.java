// WHY: Converts runtime observations and scanner indexes into a complete, fail-safe decision
// before Maven mutates its dependency set, keeping pruning policy reusable outside the plugin.

package io.github.spockz.elider.engine;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.OriginEvidence;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Retains empty-index JARs because they may contain resources.
 *
 * <p>Class-only traces lack origin data, so retain every duplicate owner.
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
public final class DependencyPruner {
  /**
   * Uses traces; refuses empty/unmatched evidence and coordinate conflicts.
   *
   * <p>Missing indexes fail only for eligible, unretained JARs.
   */
  @SuppressWarnings({
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity",
    "PMD.NPathComplexity",
    "PMD.UseConcurrentHashMap",
    "PMD.AvoidInstantiatingObjectsInLoops"
  })
  public ElisionDecision prune(
      final Collection<ArtifactFileRef> artifacts,
      final ArtifactClassIndex classIndex,
      final TraceData trace,
      final PruneConfig config) {
    final long started = System.nanoTime();
    Objects.requireNonNull(artifacts, "artifacts must not be null");
    Objects.requireNonNull(classIndex, "classIndex must not be null");
    Objects.requireNonNull(trace, "trace must not be null");
    Objects.requireNonNull(config, "config must not be null");
    if (trace.size() == 0) {
      throw new IllegalArgumentException("Cannot prune with an empty normalized runtime trace");
    }

    final Map<ArtifactCoordinate, ArtifactFileRef> byCoordinate = new HashMap<>();
    for (final ArtifactFileRef artifact : artifacts) {
      Objects.requireNonNull(artifact, "artifact must not be null");
      final ArtifactFileRef previous = byCoordinate.putIfAbsent(artifact.coordinate(), artifact);
      if (previous != null && !previous.equals(artifact)) {
        throw new IllegalArgumentException(
            "Conflicting artifact files for coordinate " + artifact.coordinate());
      }
    }

    final Set<ArtifactFileRef> uniqueArtifacts = new LinkedHashSet<>(byCoordinate.values());
    final Map<ArtifactFileRef, Set<String>> indexedClasses = classIndex.classesByArtifact();
    final Map<String, Set<ArtifactFileRef>> ownersByClass =
        ownersByClass(uniqueArtifacts, indexedClasses);
    final Set<String> observedSuppliedClasses = new HashSet<>(trace.loadedClassesDotFormat());
    observedSuppliedClasses.retainAll(ownersByClass.keySet());
    if (observedSuppliedClasses.isEmpty()) {
      throw new IllegalArgumentException(
          "Cannot prune because no observed class matches any supplied dependency");
    }
    final Map<java.nio.file.Path, Set<ArtifactFileRef>> artifactsByPath =
        artifactsByPath(uniqueArtifacts);
    final Map<String, Set<ArtifactFileRef>> observedOwnersByClass = new HashMap<>();
    for (final String className : observedSuppliedClasses) {
      observedOwnersByClass.put(
          className,
          observedOwners(
              trace.originsFor(className), ownersByClass.get(className), artifactsByPath));
    }
    final Set<ArtifactFileRef> originRetainedArtifacts = new HashSet<>();
    observedOwnersByClass.values().forEach(originRetainedArtifacts::addAll);

    final Set<ArtifactCoordinate> retained = new LinkedHashSet<>();
    final Set<ArtifactCoordinate> elided = new LinkedHashSet<>();
    final Map<ArtifactCoordinate, Set<String>> usedByArtifact = new HashMap<>();
    final Map<ArtifactCoordinate, Set<String>> unusedByArtifact = new HashMap<>();
    for (final ArtifactFileRef artifact : uniqueArtifacts) {
      final ArtifactCoordinate coordinate = artifact.coordinate();
      final boolean hasIndexEntry = indexedClasses.containsKey(artifact);
      final Set<String> used = new LinkedHashSet<>();
      final Set<String> unused = new LinkedHashSet<>();
      if (hasIndexEntry) {
        for (final String className : indexedClasses.get(artifact)) {
          if (observedOwnersByClass.getOrDefault(className, Set.of()).contains(artifact)) {
            used.add(className);
          } else {
            unused.add(className);
          }
        }
      }
      usedByArtifact.put(coordinate, used);
      unusedByArtifact.put(coordinate, unused);
      if (config.keeps(coordinate)
          || originRetainedArtifacts.contains(artifact)
          || !config.canPrune(coordinate)
          || !isJar(coordinate)) {
        retained.add(coordinate);
        continue;
      }
      if (!hasIndexEntry) {
        throw new IllegalArgumentException(
            "Missing class index entry for eligible artifact " + coordinate);
      }

      final Set<String> artifactClasses = indexedClasses.get(artifact);
      if (artifactClasses.isEmpty()) {
        retained.add(coordinate);
        continue;
      }
      if (used.isEmpty()) {
        elided.add(coordinate);
      } else {
        retained.add(coordinate);
      }
    }
    return new ElisionDecision(
        retained, elided, usedByArtifact, unusedByArtifact, System.nanoTime() - started);
  }

  private static boolean isJar(final ArtifactCoordinate coordinate) {
    return "jar".equals(coordinate.type());
  }

  private static Set<ArtifactFileRef> observedOwners(
      final OriginEvidence evidence,
      final Set<ArtifactFileRef> indexedOwners,
      final Map<java.nio.file.Path, Set<ArtifactFileRef>> artifactsByPath) {
    if (evidence.hasUnknownOrigin() || evidence.jarPaths().isEmpty()) {
      return indexedOwners;
    }
    final Set<ArtifactFileRef> matchedOwners = new HashSet<>();
    for (final java.nio.file.Path jarPath : evidence.jarPaths()) {
      final Set<ArtifactFileRef> artifactsForPath = artifactsByPath.get(jarPath);
      if (artifactsForPath == null
          || artifactsForPath.stream().noneMatch(indexedOwners::contains)) {
        return indexedOwners;
      }
      matchedOwners.addAll(artifactsForPath);
    }
    return matchedOwners;
  }

  private static Map<String, Set<ArtifactFileRef>> ownersByClass(
      final Set<ArtifactFileRef> artifacts,
      final Map<ArtifactFileRef, Set<String>> indexedClasses) {
    return artifacts.stream()
        .filter(indexedClasses::containsKey)
        .flatMap(
            artifact ->
                indexedClasses.get(artifact).stream()
                    .map(className -> Map.entry(className, artifact)))
        .collect(
            Collectors.groupingBy(
                Map.Entry::getKey, Collectors.mapping(Map.Entry::getValue, Collectors.toSet())));
  }

  private static Map<java.nio.file.Path, Set<ArtifactFileRef>> artifactsByPath(
      final Set<ArtifactFileRef> artifacts) {
    return artifacts.stream()
        .collect(
            Collectors.groupingBy(
                artifact -> artifact.filePath().toAbsolutePath().normalize(), Collectors.toSet()));
  }
}
