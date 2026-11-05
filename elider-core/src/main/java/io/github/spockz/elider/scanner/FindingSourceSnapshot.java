/* WHY: Retains each source's last-good generic claims and explicit observation state. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** One source's current or last-good generic contribution set. */
public record FindingSourceSnapshot(
    FindingSource source,
    String revision,
    Instant lastSuccessfulSync,
    Status status,
    String diagnostic,
    List<VulnerabilityFindingContribution> contributions,
    List<String> observationDiagnostics) {
  /** Source observation state, retaining last-good claims on stale and error states. */
  public enum Status {
    CURRENT,
    STALE,
    ERROR
  }

  /** Validates and snapshots one independent source observation. */
  public FindingSourceSnapshot {
    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(contributions, "contributions");
    Objects.requireNonNull(observationDiagnostics, "observationDiagnostics");
    observationDiagnostics.forEach(
        value -> {
          if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("observation diagnostics must be non-blank");
          }
        });
    observationDiagnostics = List.copyOf(observationDiagnostics);
    contributions.forEach(
        contribution -> {
          Objects.requireNonNull(contribution, "contribution");
          if (contribution.priority() != MergePriority.AUTOMATIC) {
            throw new IllegalArgumentException("manual contributions are invocation-local");
          }
        });
    contributions = List.copyOf(contributions);
    if (status == Status.CURRENT) {
      requireText(revision, "revision");
      Objects.requireNonNull(lastSuccessfulSync, "lastSuccessfulSync");
      if (diagnostic != null) {
        throw new IllegalArgumentException("current source snapshots must not carry diagnostics");
      }
    } else {
      requireText(diagnostic, "diagnostic for non-current source snapshot");
      if ((revision == null) != (lastSuccessfulSync == null)) {
        throw new IllegalArgumentException(
            "last-good revision and sync time must be retained together");
      }
      if (revision == null && !contributions.isEmpty()) {
        throw new IllegalArgumentException("source claims require a successful prior observation");
      }
    }
  }

  private static void requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
  }
}
