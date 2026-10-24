package io.github.spockz.elider.model;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/** Immutable trace of normalized class names observed at runtime. */
public record TraceData(Set<String> loadedClassesDotFormat, Set<String> loadedClassesSlashFormat) {
  /** Copies both sets so changes to inputs cannot alter the trace. */
  public TraceData {
    loadedClassesDotFormat = immutableCopy(loadedClassesDotFormat);
    loadedClassesSlashFormat = immutableCopy(loadedClassesSlashFormat);
  }

  /** Normalizes raw names into dotted and slash-separated sets. */
  public TraceData(final Set<String> rawClassNames) {
    this(buildDotSet(rawClassNames), buildSlashSet(rawClassNames));
  }

  /** Creates trace data with no observed classes. */
  public static TraceData empty() {
    return new TraceData(Set.of(), Set.of());
  }

  /** Creates a normalized trace from raw class names in either JVM name format. */
  public static TraceData of(final Set<String> rawClassNames) {
    return new TraceData(rawClassNames);
  }

  /** Matches a class name without requiring the caller to choose a JVM name format. */
  public boolean contains(final String className) {
    if (className == null) {
      return false;
    }
    if (className.indexOf('/') >= 0) {
      return loadedClassesSlashFormat.contains(className);
    }
    return loadedClassesDotFormat.contains(className);
  }

  /** Returns the number of distinct observed classes. */
  public int size() {
    return loadedClassesDotFormat.size();
  }

  /** Combines observations and reuses an input when the other trace is empty. */
  public TraceData merge(final TraceData other) {
    if (other == null || other.size() == 0) {
      return this;
    }
    if (this.size() == 0) {
      return other;
    }
    final Set<String> mergedDots = new HashSet<>(this.loadedClassesDotFormat);
    mergedDots.addAll(other.loadedClassesDotFormat);
    final Set<String> mergedSlashes = new HashSet<>(this.loadedClassesSlashFormat);
    mergedSlashes.addAll(other.loadedClassesSlashFormat);
    return new TraceData(mergedDots, mergedSlashes);
  }

  private static Set<String> immutableCopy(final Set<String> classNames) {
    return Set.copyOf(Objects.requireNonNull(classNames));
  }

  private static Set<String> buildDotSet(final Set<String> raw) {
    if (raw == null || raw.isEmpty()) {
      return Set.of();
    }
    final Set<String> result = new HashSet<>(raw.size());
    for (final String name : raw) {
      if (name != null && !name.isBlank()) {
        result.add(normalizeToDot(name.trim()));
      }
    }
    return result;
  }

  private static Set<String> buildSlashSet(final Set<String> raw) {
    if (raw == null || raw.isEmpty()) {
      return Set.of();
    }
    final Set<String> result = new HashSet<>(raw.size());
    for (final String name : raw) {
      if (name != null && !name.isBlank()) {
        result.add(normalizeToSlash(name.trim()));
      }
    }
    return result;
  }

  /** Converts class file paths and slash-separated JVM names to dotted notation. */
  public static String normalizeToDot(final String className) {
    String clean = className;
    if (clean.endsWith(".class")) {
      clean = clean.substring(0, clean.length() - 6);
    }
    return clean.replace('/', '.');
  }

  /** Converts class file paths and dotted JVM names to slash-separated notation. */
  public static String normalizeToSlash(final String className) {
    String clean = className;
    if (clean.endsWith(".class")) {
      clean = clean.substring(0, clean.length() - 6);
    }
    return clean.replace('.', '/');
  }
}
