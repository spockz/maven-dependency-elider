/* WHY: Stores source health independently from findings. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.FindingSource;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** One source observation, including explicit cache or producer unavailability. */
record FindingSourceObservation(
    Optional<FindingSource> source,
    Status status,
    String revision,
    Instant lastSuccessfulSync,
    String diagnostic,
    List<String> observationDiagnostics,
    int contributionCount) {
  FindingSourceObservation {
    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(status, "status");
    observationDiagnostics =
        List.copyOf(Objects.requireNonNull(observationDiagnostics, "observationDiagnostics"));
    FindingSourceObservationValidator.validate(
        source,
        status,
        revision,
        lastSuccessfulSync,
        diagnostic,
        observationDiagnostics,
        contributionCount);
  }

  /** Source-observation lifecycle state. */
  /* package */ enum Status {
    CURRENT,
    STALE,
    ERROR,
    UNAVAILABLE
  }
}
