/* WHY: Evaluates OSV range events separately from package-level exact-version claims. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.OsvAffectedRange;
import java.util.Map;
import org.apache.maven.artifact.versioning.ComparableVersion;

/** Parses one raw OSV interval sequence. */
final class OsvRangeEvaluator {
  /** Required event field count for supported boundaries. */
  private static final int SINGLE_EVENT_FIELD = 1;

  /** Lower-bound event name. */
  private static final String INTRODUCED = "introduced";

  /** Inclusive upper-bound event name. */
  private static final String LAST_AFFECTED = "last_affected";

  /** OSV sentinel before every Maven version. */
  private static final String ZERO_SENTINEL = "0";

  /** Exclusive upper-bound event name. */
  private static final String FIXED = "fixed";

  private OsvRangeEvaluator() {}

  /** Evaluates one source range for a concrete candidate. */
  /* package */ static MavenRawScopeApplicability.Result evaluate(
      final OsvAffectedRange range, final String version) {
    if (!"ECOSYSTEM".equalsIgnoreCase(range.type()) || range.repo() != null) {
      return MavenRawScopeApplicability.unknown(
          "OSV range type or repository is unsupported for Maven");
    }
    if (range.events().isEmpty()) {
      return MavenRawScopeApplicability.unknown("OSV range has no events");
    }
    final RangeState state = new RangeState(version);
    for (final Map<String, String> event : range.events()) {
      final MavenRawScopeApplicability.Result failure = state.accept(event);
      if (failure != null) {
        return failure;
      }
    }
    return state.finish();
  }

  /** Accumulates the disjoint intervals represented by one raw range. */
  private static final class RangeState {
    /** Candidate version being evaluated. */
    private final String version;

    /** Current interval lower bound when an interval is open. */
    private String introduced = "";

    /** Whether an interval currently has the {@code introduced} lower bound. */
    private boolean hasOpenInterval;

    /** Upper bound of the prior interval. */
    private String previousUpper;

    /** Whether the prior interval included its upper bound. */
    private boolean previousUpperInclusive;

    /** Whether an interval includes the candidate. */
    private boolean matched;

    private RangeState(final String version) {
      this.version = version;
    }

    private MavenRawScopeApplicability.Result accept(final Map<String, String> event) {
      if (event.size() != SINGLE_EVENT_FIELD) {
        return MavenRawScopeApplicability.unknown("OSV range event has unsupported fields");
      }
      final Map.Entry<String, String> field = event.entrySet().iterator().next();
      if (field.getValue() == null || field.getValue().isBlank()) {
        return MavenRawScopeApplicability.unknown("OSV range boundary is blank");
      }
      return switch (field.getKey()) {
        case INTRODUCED -> introduce(field.getValue());
        case FIXED, LAST_AFFECTED -> close(field.getKey(), field.getValue());
        default -> MavenRawScopeApplicability.unknown("OSV range event is unsupported for Maven");
      };
    }

    private MavenRawScopeApplicability.Result introduce(final String boundary) {
      if (hasOpenInterval) {
        return MavenRawScopeApplicability.unknown(
            "OSV range introduces a second interval before closing the first");
      }
      if (!isAfterPrevious(boundary)) {
        return MavenRawScopeApplicability.unknown("OSV range intervals overlap or are unordered");
      }
      introduced = boundary;
      hasOpenInterval = true;
      return null;
    }

    private boolean isAfterPrevious(final String boundary) {
      if (previousUpper == null) {
        return true;
      }
      final int comparison =
          new ComparableVersion(boundary).compareTo(new ComparableVersion(previousUpper));
      return comparison > 0 || (comparison == 0 && !previousUpperInclusive);
    }

    private MavenRawScopeApplicability.Result close(final String eventType, final String upper) {
      if (!hasOpenInterval) {
        return MavenRawScopeApplicability.unknown(
            "OSV range closes an interval without an introduction");
      }
      final boolean inclusiveUpper = LAST_AFFECTED.equals(eventType);
      if (!validInterval(introduced, upper, inclusiveUpper)) {
        return MavenRawScopeApplicability.unknown("OSV range boundaries are empty or reversed");
      }
      final MavenRawScopeApplicability.Result interval =
          evaluateInterval(introduced, upper, inclusiveUpper, version);
      if (interval.status() == MavenRawScopeApplicability.Status.UNKNOWN) {
        return interval;
      }
      matched |= interval.status() == MavenRawScopeApplicability.Status.AFFECTED;
      previousUpper = upper;
      previousUpperInclusive = inclusiveUpper;
      hasOpenInterval = false;
      return null;
    }

    private MavenRawScopeApplicability.Result finish() {
      if (hasOpenInterval) {
        final MavenRawScopeApplicability.Result interval =
            evaluateInterval(introduced, null, false, version);
        if (interval.status() == MavenRawScopeApplicability.Status.UNKNOWN) {
          return interval;
        }
        matched |= interval.status() == MavenRawScopeApplicability.Status.AFFECTED;
      }
      return matched
          ? MavenRawScopeApplicability.affected("Candidate is inside this raw OSV range")
          : MavenRawScopeApplicability.unaffected("Candidate is outside this raw OSV range");
    }
  }

  private static MavenRawScopeApplicability.Result evaluateInterval(
      final String lower, final String upper, final boolean inclusiveUpper, final String version) {
    if (ZERO_SENTINEL.equals(lower) && upper == null) {
      return MavenRawScopeApplicability.affected(
          "Candidate is inside an OSV range introduced before all Maven versions");
    }
    final String specification = intervalSpecification(lower, upper, inclusiveUpper);
    try {
      MavenVersionRangeMatcher.validate(specification);
      return MavenVersionRangeMatcher.includes(specification, version)
          ? MavenRawScopeApplicability.affected("Candidate is inside a supported Maven interval")
          : MavenRawScopeApplicability.unaffected(
              "Candidate is outside a supported Maven interval");
    } catch (final IllegalArgumentException exception) {
      return MavenRawScopeApplicability.unknown(
          "OSV range cannot be evaluated with Maven version semantics");
    }
  }

  private static String intervalSpecification(
      final String lower, final String upper, final boolean inclusiveUpper) {
    if (ZERO_SENTINEL.equals(lower)) {
      return "(," + upper + (inclusiveUpper ? "]" : ")");
    }
    return upper == null
        ? "[" + lower + ",)"
        : "[" + lower + "," + upper + (inclusiveUpper ? "]" : ")");
  }

  private static boolean validInterval(
      final String lower, final String upper, final boolean inclusiveUpper) {
    final int comparison = new ComparableVersion(lower).compareTo(new ComparableVersion(upper));
    return comparison < 0 || (comparison == 0 && inclusiveUpper);
  }
}
