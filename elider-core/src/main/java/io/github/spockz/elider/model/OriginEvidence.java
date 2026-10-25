/* WHY: Preserves whether a class observation names the exact local JAR or leaves ownership
 * ambiguous, so pruning can narrow duplicate owners only when source evidence is complete. */

package io.github.spockz.elider.model;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/** Immutable class origin evidence, including unresolved ambiguity. */
public record OriginEvidence(Set<Path> jarPaths, boolean hasUnknownOrigin) {
  /** Requires absolute paths for safe artifact identification. */
  public OriginEvidence {
    Objects.requireNonNull(jarPaths, "jarPaths must not be null");
    final Set<Path> normalizedPaths = new HashSet<>();
    for (final Path jarPath : jarPaths) {
      final Path nonNullPath = Objects.requireNonNull(jarPath, "jar path must not be null");
      if (!nonNullPath.isAbsolute()) {
        throw new IllegalArgumentException("JAR origin paths must be absolute");
      }
      normalizedPaths.add(nonNullPath.normalize());
    }
    if (normalizedPaths.isEmpty() && !hasUnknownOrigin) {
      throw new IllegalArgumentException("Origin evidence needs a JAR path or unknown origin");
    }
    jarPaths = Set.copyOf(normalizedPaths);
  }

  /** Creates ambiguity evidence for class-only observations. */
  public static OriginEvidence unknown() {
    return new OriginEvidence(Set.of(), true);
  }

  /** Combines origins without erasing ambiguity. */
  public OriginEvidence merge(final OriginEvidence other) {
    Objects.requireNonNull(other, "other must not be null");
    final Set<Path> mergedPaths = new HashSet<>(jarPaths);
    mergedPaths.addAll(other.jarPaths);
    return new OriginEvidence(mergedPaths, hasUnknownOrigin || other.hasUnknownOrigin);
  }
}
