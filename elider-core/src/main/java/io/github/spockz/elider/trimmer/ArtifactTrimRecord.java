/* WHY: Captures immutable input and output provenance for one per-artifact JAR trim. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;

/** Hash and pruning provenance for a sanitized dependency archive. */
/* WHY: This persisted record exposes each metric as a direct immutable component. */
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
    long prunedClassBytes,
    Optional<PhysicalEntryMetrics> physicalEntryMetrics,
    String mrjarStatus) {

  /** Preserves the legacy constructor. */
  @SuppressWarnings("PMD.ExcessiveParameterList")
  public ArtifactTrimRecord(
      final ArtifactCoordinate coordinate,
      final Path originalPath,
      final String originalSha256,
      final String originalSha1,
      final Path trimmedPath,
      final String trimmedSha256,
      final String trimmedSha1,
      final int totalClasses,
      final int retainedClasses,
      final long prunedClassBytes) {
    this(
        coordinate,
        originalPath,
        originalSha256,
        originalSha1,
        trimmedPath,
        trimmedSha256,
        trimmedSha1,
        totalClasses,
        retainedClasses,
        prunedClassBytes,
        Optional.empty(),
        "not_multi_release");
  }

  /** Creates a record with exact physical archive entry counts. */
  @SuppressWarnings("PMD.ExcessiveParameterList")
  public ArtifactTrimRecord(
      final ArtifactCoordinate coordinate,
      final Path originalPath,
      final String originalSha256,
      final String originalSha1,
      final Path trimmedPath,
      final String trimmedSha256,
      final String trimmedSha1,
      final int totalClasses,
      final int retainedClasses,
      final long prunedClassBytes,
      final int originalPhysicalEntries,
      final int trimmedPhysicalEntries,
      final String mrjarStatus) {
    this(
        coordinate,
        originalPath,
        originalSha256,
        originalSha1,
        trimmedPath,
        trimmedSha256,
        trimmedSha1,
        totalClasses,
        retainedClasses,
        prunedClassBytes,
        Optional.of(new PhysicalEntryMetrics(originalPhysicalEntries, trimmedPhysicalEntries)),
        mrjarStatus);
  }

  /** Validates that the record describes an actual trim with complete digests. */
  public ArtifactTrimRecord {
    Objects.requireNonNull(coordinate, "coordinate");
    Objects.requireNonNull(originalPath, "originalPath");
    Objects.requireNonNull(trimmedPath, "trimmedPath");
    requireSha256(originalSha256, "originalSha256");
    requireSha1(originalSha1, "originalSha1");
    requireSha256(trimmedSha256, "trimmedSha256");
    requireSha1(trimmedSha1, "trimmedSha1");
    Objects.requireNonNull(physicalEntryMetrics, "physicalEntryMetrics");
    Objects.requireNonNull(mrjarStatus, "mrjarStatus");
    if (totalClasses < 0
        || retainedClasses < 0
        || retainedClasses > totalClasses
        || prunedClassBytes < 0) {
      throw new IllegalArgumentException("Invalid class counts or pruned-class byte total");
    }
    if (!"not_multi_release".equals(mrjarStatus) && !"elevated_and_trimmed".equals(mrjarStatus)) {
      throw new IllegalArgumentException("Unsupported MRJAR trim status: " + mrjarStatus);
    }
  }

  /** Exact physical ZIP-entry counts when captured by ArchiveSanitizer. */
  public OptionalInt originalPhysicalEntries() {
    return physicalEntryMetrics
        .map(metrics -> OptionalInt.of(metrics.originalEntries()))
        .orElseGet(OptionalInt::empty);
  }

  /** Exact physical ZIP-entry counts when captured by ArchiveSanitizer. */
  public OptionalInt trimmedPhysicalEntries() {
    return physicalEntryMetrics
        .map(metrics -> OptionalInt.of(metrics.trimmedEntries()))
        .orElseGet(OptionalInt::empty);
  }

  /** Counts physical ZIP entries in the source and trimmed archives. */
  public record PhysicalEntryMetrics(int originalEntries, int trimmedEntries) {
    /** Validates that both physical entry counts are known. */
    public PhysicalEntryMetrics {
      if (originalEntries < 0 || trimmedEntries < 0) {
        throw new IllegalArgumentException("Physical archive entry counts must be nonnegative");
      }
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
