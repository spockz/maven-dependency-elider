/* WHY: Gives advisory evidence a shared, immutable Maven product and version boundary. */

package io.github.spockz.elider.model;

import java.util.Objects;

/** Exact CVE, Maven component, and affected-version scope for advisory evidence. */
public record AdvisoryScope(
    String cveId, ArtifactCoordinate affectedCoordinate, String versionRangeSpec) {
  /** Validates the advisory identity and affected product scope. */
  public AdvisoryScope {
    if (cveId == null || !cveId.matches("CVE-[0-9]{4}-[0-9]{4,}")) {
      throw new IllegalArgumentException("cveId must be a CVE identifier");
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
  }
}
