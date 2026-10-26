package io.github.spockz.elider.model;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

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

  // This copied map is immutable before publication and is never mutated afterward.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<ArtifactCoordinate, Set<String>> immutableClassMap(
      final Map<ArtifactCoordinate, Set<String>> classesByArtifact) {
    final Map<ArtifactCoordinate, Set<String>> immutableCopy =
        new HashMap<>(
            Objects.requireNonNull(classesByArtifact, "class map must not be null").size());
    classesByArtifact.forEach(
        (coordinate, classes) ->
            immutableCopy.put(
                Objects.requireNonNull(coordinate, "class map coordinate must not be null"),
                immutableSet(Objects.requireNonNull(classes, "class set must not be null"))));
    return Collections.unmodifiableMap(immutableCopy);
  }
}
