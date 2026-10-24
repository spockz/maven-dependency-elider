package io.github.spockz.elider.model;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** The immutable outcome of dependency elision analysis. */
public record ElisionDecision(
    Set<ArtifactCoordinate> retainedArtifacts,
    Set<ArtifactCoordinate> elidedArtifacts,
    Map<ArtifactCoordinate, Set<String>> retainedClassesPerArtifact,
    Map<ArtifactCoordinate, Set<String>> unusedClassesPerArtifact,
    long elapsedNanos) {
  /** Freezes result values so callers cannot change an analysis after it completes. */
  public ElisionDecision {
    retainedArtifacts = immutableSet(retainedArtifacts);
    elidedArtifacts = immutableSet(elidedArtifacts);
    retainedClassesPerArtifact = immutableClassMap(retainedClassesPerArtifact);
    unusedClassesPerArtifact = immutableClassMap(unusedClassesPerArtifact);
  }

  /** Reports whether the supplied artifact was removed by this decision. */
  public boolean isElided(final ArtifactCoordinate coordinate) {
    return elidedArtifacts.contains(coordinate);
  }

  /** Reports whether the supplied artifact remains in the dependency set. */
  public boolean isRetained(final ArtifactCoordinate coordinate) {
    return retainedArtifacts.contains(coordinate);
  }

  /** Returns the number of artifacts included in this decision. */
  public int totalArtifacts() {
    return retainedArtifacts.size() + elidedArtifacts.size();
  }

  /** Returns how many artifacts were removed. */
  public int elidedCount() {
    return elidedArtifacts.size();
  }

  /** Returns how many artifacts remain. */
  public int retainedCount() {
    return retainedArtifacts.size();
  }

  /** Returns used classes for the artifact, or none when it has no entry. */
  public Set<String> getRetainedClasses(final ArtifactCoordinate coordinate) {
    return retainedClassesPerArtifact.getOrDefault(coordinate, Set.of());
  }

  /** Returns unused classes for the artifact, or none when it has no entry. */
  public Set<String> getUnusedClasses(final ArtifactCoordinate coordinate) {
    return unusedClassesPerArtifact.getOrDefault(coordinate, Set.of());
  }

  private static <T> Set<T> immutableSet(final Set<T> values) {
    return Set.copyOf(values);
  }

  private static Map<ArtifactCoordinate, Set<String>> immutableClassMap(
      final Map<ArtifactCoordinate, Set<String>> classesByArtifact) {
    return classesByArtifact.entrySet().stream()
        .collect(
            Collectors.toUnmodifiableMap(
                Map.Entry::getKey, entry -> immutableSet(entry.getValue())));
  }
}
