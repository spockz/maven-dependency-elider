/* WHY: Binds Snyk findings and diagnostics to the exact package version queried. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.util.List;
import java.util.Objects;

/** One immutable result for an exact Snyk package query. */
public record SnykPackageIssuesResult(
    ArtifactCoordinate coordinate,
    Status status,
    List<VulnerabilityFindingContribution> contributions,
    List<String> diagnostics) {
  /** Result completeness for one exact package query. */
  public enum Status {
    COMPLETE,
    PARTIAL,
    FAILED
  }

  /** Validates and snapshots findings and diagnostics. */
  public SnykPackageIssuesResult {
    Objects.requireNonNull(coordinate, "coordinate");
    Objects.requireNonNull(status, "status");
    contributions = List.copyOf(contributions);
    diagnostics = List.copyOf(diagnostics);
  }
}
