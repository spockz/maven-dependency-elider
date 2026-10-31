/* WHY: Gives advisory evidence a shared immutable Maven scope. */

package io.github.spockz.elider.model;

import java.util.Objects;

/** Maven product and affected-version scope for advisory evidence. */
public record AdvisoryScope(
    String cveId,
    ArtifactCoordinate affectedCoordinate,
    String versionRangeSpec,
    String ecosystem,
    String packageName) {
  /** Creates a scope for owner-configured or existing Maven-only callers. */
  public AdvisoryScope(
      final String cveId,
      final ArtifactCoordinate affectedCoordinate,
      final String versionRangeSpec) {
    this(
        cveId,
        affectedCoordinate,
        versionRangeSpec,
        "Maven",
        affectedCoordinate.groupId() + ":" + affectedCoordinate.artifactId());
  }

  /** Validates the advisory identity and affected product scope. */
  public AdvisoryScope {
    if (cveId != null && !cveId.matches("CVE-[0-9]{4}-[0-9]{4,}")) {
      throw new IllegalArgumentException("cveId must be null or a CVE identifier");
    }
    Objects.requireNonNull(affectedCoordinate, "affectedCoordinate");
    if (affectedCoordinate.groupId().isBlank() || affectedCoordinate.artifactId().isBlank()) {
      throw new IllegalArgumentException(
          "affectedCoordinate groupId and artifactId must not be blank");
    }
    if (affectedCoordinate.version() != null && affectedCoordinate.version().isBlank()) {
      throw new IllegalArgumentException("affectedCoordinate.version must not be blank");
    }
    if (versionRangeSpec == null || versionRangeSpec.isBlank()) {
      throw new IllegalArgumentException("versionRangeSpec must not be blank");
    }
    if (ecosystem == null || ecosystem.isBlank()) {
      throw new IllegalArgumentException("ecosystem must not be blank");
    }
    if (packageName == null || packageName.isBlank()) {
      throw new IllegalArgumentException("packageName must not be blank");
    }
  }
}
