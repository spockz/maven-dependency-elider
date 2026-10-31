/* WHY: Keeps prose candidates
 * separate from verified evidence. */

package io.github.spockz.elider.model;

import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Review-only candidates mined from prose or references. */
public record HeuristicCandidateEvidence(
    AdvisoryScope scope,
    AdvisoryProvenance provenance,
    Set<String> candidateClasses,
    Set<String> candidateDependencies)
    implements AdvisoryEvidence {
  /** Validates candidate values and freezes their sets. */
  public HeuristicCandidateEvidence {
    Objects.requireNonNull(scope, "scope");
    Objects.requireNonNull(provenance, "provenance");
    if (provenance.origin() != EvidenceOrigin.DESCRIPTION
        && provenance.origin() != EvidenceOrigin.REFERENCE_URL) {
      throw new IllegalArgumentException(
          "Heuristic evidence requires prose or reference provenance");
    }
    candidateClasses = immutableStrings(candidateClasses, "candidateClasses");
    candidateDependencies = immutableStrings(candidateDependencies, "candidateDependencies");
    if (candidateClasses.isEmpty() && candidateDependencies.isEmpty()) {
      throw new IllegalArgumentException("Heuristic evidence requires at least one candidate");
    }
    if (candidateClasses.stream().anyMatch(value -> !isTopLevelClassName(value))) {
      throw new IllegalArgumentException("candidateClasses must contain top-level class names");
    }
    if (candidateDependencies.stream().anyMatch(value -> !isExactDependency(value))) {
      throw new IllegalArgumentException(
          "candidateDependencies must be exact group:artifact values");
    }
  }

  @Override
  public ConfidenceLevel confidenceLabel() {
    return ConfidenceLevel.MEDIUM;
  }

  private static Set<String> immutableStrings(final Set<String> values, final String field) {
    Objects.requireNonNull(values, field);
    final Set<String> copy = new TreeSet<>();
    for (final String value : values) {
      if (value == null || value.isBlank()) {
        throw new IllegalArgumentException(field + " must contain non-blank strings");
      }
      copy.add(value);
    }
    return Set.copyOf(copy);
  }

  private static boolean isTopLevelClassName(final String value) {
    return value.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")
        && value.indexOf('$') < 0;
  }

  private static boolean isExactDependency(final String value) {
    return value.matches("[A-Za-z0-9_][A-Za-z0-9_.-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*");
  }
}
