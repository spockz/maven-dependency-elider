/* WHY: Captures immutable input and output provenance for one per-artifact JAR trim. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.nio.file.Path;
import java.util.Objects;

/** Hash and pruning provenance for a sanitized dependency archive. */
public record ArtifactTrimRecord(
    ArtifactCoordinate coordinate,
    Path originalPath,
    String originalSha256,
    String originalSha1,
    Path trimmedPath,
    String trimmedSha256,
    String trimmedSha1,
    int totalClasses,
    int retainedClasses,
    long prunedClassBytes) {

  /** Validates that the record describes an actual trim with complete digests. */
  public ArtifactTrimRecord {
    Objects.requireNonNull(coordinate, "coordinate");
    Objects.requireNonNull(originalPath, "originalPath");
    Objects.requireNonNull(trimmedPath, "trimmedPath");
    requireSha256(originalSha256, "originalSha256");
    requireSha1(originalSha1, "originalSha1");
    requireSha256(trimmedSha256, "trimmedSha256");
    requireSha1(trimmedSha1, "trimmedSha1");
    if (totalClasses < 0
        || retainedClasses < 0
        || retainedClasses > totalClasses
        || prunedClassBytes < 0) {
      throw new IllegalArgumentException("Invalid class counts or pruned-class byte total");
    }
  }

  private static void requireSha256(final String digest, final String field) {
    if (digest == null || !digest.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException(field + " must be a lowercase SHA-256 digest");
    }
  }

  private static void requireSha1(final String digest, final String field) {
    if (digest == null || !digest.matches("[0-9a-f]{40}")) {
      throw new IllegalArgumentException(field + " must be a lowercase SHA-1 digest");
    }
  }
}
