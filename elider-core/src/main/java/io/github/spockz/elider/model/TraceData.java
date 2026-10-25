/* WHY: Keeps normalized runtime classes and their source ambiguity together so pruning can use
 * complete artifact evidence without losing the conservative class-only merge behavior. */

package io.github.spockz.elider.model;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Immutable trace of normalized class names observed at runtime. */
@SuppressWarnings("PMD.UseConcurrentHashMap")
public record TraceData(
    Set<String> loadedClassesDotFormat,
    Set<String> loadedClassesSlashFormat,
    Map<String, OriginEvidence> originEvidenceByClass) {
  /** Copies all collections so caller changes cannot alter class or origin evidence. */
  public TraceData {
    loadedClassesDotFormat = immutableCopy(loadedClassesDotFormat);
    loadedClassesSlashFormat = immutableCopy(loadedClassesSlashFormat);
    Objects.requireNonNull(originEvidenceByClass, "originEvidenceByClass must not be null");
    final Map<String, OriginEvidence> evidenceCopy = new HashMap<>();
    for (final Map.Entry<String, OriginEvidence> entry : originEvidenceByClass.entrySet()) {
      final String className =
          Objects.requireNonNull(entry.getKey(), "class name must not be null");
      if (!loadedClassesDotFormat.contains(className)) {
        throw new IllegalArgumentException("Origin evidence has no matching observed class");
      }
      evidenceCopy.put(
          className, Objects.requireNonNull(entry.getValue(), "origin evidence must not be null"));
    }
    if (!evidenceCopy.keySet().equals(loadedClassesDotFormat)) {
      throw new IllegalArgumentException("Every observed class must have origin evidence");
    }
    originEvidenceByClass = Map.copyOf(evidenceCopy);
  }

  /** Preserves the original class-set constructor while marking origins unknown. */
  public TraceData(
      final Set<String> loadedClassesDotFormat, final Set<String> loadedClassesSlashFormat) {
    this(loadedClassesDotFormat, loadedClassesSlashFormat, unknownOrigins(loadedClassesDotFormat));
  }

  /** Normalizes raw names into dotted and slash-separated sets. */
  public TraceData(final Set<String> rawClassNames) {
    this(
        buildDotSet(rawClassNames),
        buildSlashSet(rawClassNames),
        unknownOrigins(buildDotSet(rawClassNames)));
  }

  /** Creates trace data with no observed classes. */
  public static TraceData empty() {
    return new TraceData(Set.of(), Set.of());
  }

  /** Creates a normalized trace from raw class names in either JVM name format. */
  public static TraceData of(final Set<String> rawClassNames) {
    return new TraceData(rawClassNames);
  }

  /** Creates a trace with source evidence for each class. */
  public static TraceData fromClassOrigins(final Map<String, OriginEvidence> classOrigins) {
    Objects.requireNonNull(classOrigins, "classOrigins must not be null");
    final Map<String, OriginEvidence> normalizedOrigins = new HashMap<>();
    for (final Map.Entry<String, OriginEvidence> entry : classOrigins.entrySet()) {
      final String className =
          normalizeToDot(Objects.requireNonNull(entry.getKey(), "class name must not be null"));
      final OriginEvidence evidence =
          Objects.requireNonNull(entry.getValue(), "origin evidence must not be null");
      normalizedOrigins.merge(className, evidence, OriginEvidence::merge);
    }
    final Set<String> dottedNames = Set.copyOf(normalizedOrigins.keySet());
    final Set<String> slashNames = new HashSet<>();
    for (final String dottedName : dottedNames) {
      slashNames.add(normalizeToSlash(dottedName));
    }
    return new TraceData(dottedNames, slashNames, normalizedOrigins);
  }

  /** Returns source evidence for a class that is present in this trace. */
  public OriginEvidence originsFor(final String className) {
    final String dottedName = normalizeToDot(Objects.requireNonNull(className, "className"));
    final OriginEvidence evidence = originEvidenceByClass.get(dottedName);
    if (evidence == null) {
      throw new IllegalArgumentException("Class is not present in this trace: " + className);
    }
    return evidence;
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
    final Map<String, OriginEvidence> mergedOrigins = new HashMap<>(originEvidenceByClass);
    other.originEvidenceByClass.forEach(
        (className, evidence) -> mergedOrigins.merge(className, evidence, OriginEvidence::merge));
    return new TraceData(mergedDots, mergedSlashes, mergedOrigins);
  }

  private static Map<String, OriginEvidence> unknownOrigins(final Set<String> classNames) {
    final Map<String, OriginEvidence> origins = new HashMap<>();
    for (final String className : Objects.requireNonNull(classNames, "classNames")) {
      origins.put(className, OriginEvidence.unknown());
    }
    return origins;
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
