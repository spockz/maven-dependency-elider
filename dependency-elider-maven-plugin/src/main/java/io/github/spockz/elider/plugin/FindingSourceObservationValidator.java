/* WHY: Enforces cache and source health invariants before observations are saved. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.FindingSource;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Validates the state distinctions represented by a finding source observation. */
final class FindingSourceObservationValidator {
  private FindingSourceObservationValidator() {}

  /* package */ static void validate(
      final Optional<FindingSource> source,
      final FindingSourceObservation.Status status,
      final String revision,
      final Instant lastSuccessfulSync,
      final String diagnostic,
      final List<String> observationDiagnostics,
      final int contributionCount) {
    observationDiagnostics.forEach(value -> requireText(value, "observation diagnostic"));
    if (contributionCount < 0) {
      throw new IllegalArgumentException("contributionCount must not be negative");
    }
    if (status == FindingSourceObservation.Status.UNAVAILABLE) {
      validateUnavailable(source, revision, lastSuccessfulSync, diagnostic);
      return;
    }
    if (status == FindingSourceObservation.Status.ERROR && source.isEmpty()) {
      validateCacheError(revision, lastSuccessfulSync, diagnostic);
      return;
    }
    validateSourceObservation(source, status, revision, lastSuccessfulSync, diagnostic);
  }

  private static void validateUnavailable(
      final Optional<FindingSource> source,
      final String revision,
      final Instant lastSuccessfulSync,
      final String diagnostic) {
    if (source.isPresent() || revision != null || lastSuccessfulSync != null) {
      throw new IllegalArgumentException("unavailable cache observations have no source revision");
    }
    requireText(diagnostic, "diagnostic");
  }

  private static void validateCacheError(
      final String revision, final Instant lastSuccessfulSync, final String diagnostic) {
    if (revision != null || lastSuccessfulSync != null) {
      throw new IllegalArgumentException("cache errors have no source revision");
    }
    requireText(diagnostic, "diagnostic");
  }

  private static void validateSourceObservation(
      final Optional<FindingSource> source,
      final FindingSourceObservation.Status status,
      final String revision,
      final Instant lastSuccessfulSync,
      final String diagnostic) {
    Objects.requireNonNull(source.orElse(null), "source for available observation");
    if (status == FindingSourceObservation.Status.CURRENT) {
      requireText(revision, "revision");
      Objects.requireNonNull(lastSuccessfulSync, "lastSuccessfulSync");
      if (diagnostic != null) {
        throw new IllegalArgumentException("current observations must not carry a diagnostic");
      }
      return;
    }
    requireText(diagnostic, "diagnostic");
  }

  private static void requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
  }
}
