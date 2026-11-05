/* WHY: Keeps unsupported predicates separate from normalized coverage. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.applicability.MavenVersionRangeMatcher;

/** One affected or unaffected predicate, supported or unresolved. */
public record VersionCoverageClaim(
    String rawPredicate,
    String normalizedMavenRange,
    VersionApplicability status,
    String diagnostic)
    implements Comparable<VersionCoverageClaim> {
  /** Validates supported and unresolved claim states. */
  public VersionCoverageClaim {
    requireText(rawPredicate, "rawPredicate");
    if (status == null) {
      throw new IllegalArgumentException("status must not be null");
    }
    if (status == VersionApplicability.UNRESOLVED) {
      requireText(diagnostic, "diagnostic for unresolved predicate");
    } else if (normalizedMavenRange == null) {
      throw new IllegalArgumentException("resolved coverage requires a Maven range");
    }
    if (normalizedMavenRange == null) {
      if (diagnostic != null && diagnostic.isBlank()) {
        throw new IllegalArgumentException("diagnostic must not be blank when present");
      }
    } else {
      MavenVersionRangeMatcher.validate(normalizedMavenRange);
      if (diagnostic != null && diagnostic.isBlank()) {
        throw new IllegalArgumentException("diagnostic must not be blank when present");
      }
    }
  }

  /** Creates a supported affected range. */
  public static VersionCoverageClaim affected(final String mavenRange) {
    return new VersionCoverageClaim(mavenRange, mavenRange, VersionApplicability.AFFECTED, null);
  }

  /** Creates a supported unaffected range. */
  public static VersionCoverageClaim unaffected(final String mavenRange) {
    return new VersionCoverageClaim(
        mavenRange, mavenRange, VersionApplicability.NOT_AFFECTED, null);
  }

  /** Creates an affected predicate that cannot be evaluated. */
  public static VersionCoverageClaim unresolvedAffected(
      final String rawPredicate, final String diagnostic) {
    return new VersionCoverageClaim(
        rawPredicate, null, VersionApplicability.UNRESOLVED, diagnostic);
  }

  /** Creates an unaffected predicate that cannot be evaluated. */
  public static VersionCoverageClaim unresolvedUnaffected(
      final String rawPredicate, final String diagnostic) {
    return new VersionCoverageClaim(
        rawPredicate, null, VersionApplicability.UNRESOLVED, diagnostic);
  }

  /** Creates a bounded predicate whose status cannot be normalized safely. */
  public static VersionCoverageClaim unresolvedRange(
      final String mavenRange, final String diagnostic) {
    return new VersionCoverageClaim(
        mavenRange, mavenRange, VersionApplicability.UNRESOLVED, diagnostic);
  }

  @Override
  public int compareTo(final VersionCoverageClaim other) {
    final int rawOrder = rawPredicate.compareTo(other.rawPredicate);
    if (rawOrder != 0) {
      return rawOrder;
    }
    final int normalizedOrder =
        java.util.Comparator.nullsFirst(String::compareTo)
            .compare(normalizedMavenRange, other.normalizedMavenRange);
    if (normalizedOrder != 0) {
      return normalizedOrder;
    }
    final int statusOrder = status.compareTo(other.status);
    if (statusOrder != 0) {
      return statusOrder;
    }
    return java.util.Comparator.nullsFirst(String::compareTo).compare(diagnostic, other.diagnostic);
  }

  private static void requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
  }
}
