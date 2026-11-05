/* WHY: Keeps OSV event conversion separate from package identity and finding assembly. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.applicability.MavenVersionRangeMatcher;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedRange;
import io.github.spockz.elider.model.VersionCoverageClaim;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.maven.artifact.versioning.ComparableVersion;

/** Converts supported OSV ecosystem range events into Maven affected intervals. */
final class OsvEcosystemRangeNormalizer {
  /** Event objects are supported when they contain exactly one operator. */
  private static final int EVENT_FIELD_COUNT = 1;

  /** OSV event that opens an affected interval. */
  private static final String INTRODUCED = "introduced";

  /** Unsupported OSV event with an independent upper constraint. */
  private static final String LIMIT = "limit";

  /** OSV event that closes an affected interval exclusively. */
  private static final String FIXED = "fixed";

  /** OSV event that closes an affected interval inclusively. */
  private static final String LAST_AFFECTED = "last_affected";

  private OsvEcosystemRangeNormalizer() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static List<VersionCoverageClaim> normalize(
      final OsvAdvisoryRecord record, final OsvAffectedRange range) {
    if (range.repo() != null) {
      return unresolved(record, range, "OSV repository ranges are not Maven ecosystem predicates");
    }
    final Optional<List<Map<String, String>>> sortedEvents = sortedEvents(range);
    if (sortedEvents.isEmpty()) {
      return unresolved(record, range, "OSV range events are unsupported or ambiguous");
    }
    final List<Map<String, String>> events = sortedEvents.orElseThrow();
    final RangeState state = new RangeState(record, range);
    for (final Map<String, String> event : events) {
      if (!state.accept(event)) {
        return unresolved(record, range, state.failure());
      }
    }
    return state.finish();
  }

  private static Optional<List<Map<String, String>>> sortedEvents(final OsvAffectedRange range) {
    final List<Map<String, String>> events = new ArrayList<>(range.events());
    for (final Map<String, String> event : events) {
      if (!hasSingleField(event)) {
        return Optional.empty();
      }
    }
    events.sort(OsvEcosystemRangeNormalizer::compareEvents);
    for (int index = 1; index < events.size(); index++) {
      if (compareEvents(events.get(index - 1), events.get(index)) == 0) {
        return Optional.empty();
      }
    }
    return Optional.of(events);
  }

  private static boolean hasSingleField(final Map<String, String> event) {
    return event.size() == EVENT_FIELD_COUNT;
  }

  private static int compareEvents(
      final Map<String, String> left, final Map<String, String> right) {
    final Map.Entry<String, String> leftEvent = left.entrySet().iterator().next();
    final Map.Entry<String, String> rightEvent = right.entrySet().iterator().next();
    final int leftZero = introducedZero(leftEvent) ? 0 : 1;
    final int rightZero = introducedZero(rightEvent) ? 0 : 1;
    if (leftZero != rightZero) {
      return Integer.compare(leftZero, rightZero);
    }
    return compareVersions(leftEvent.getValue(), rightEvent.getValue());
  }

  private static boolean introducedZero(final Map.Entry<String, String> event) {
    return INTRODUCED.equals(event.getKey()) && "0".equals(event.getValue());
  }

  private static int compareVersions(final String left, final String right) {
    return new ComparableVersion(left).compareTo(new ComparableVersion(right));
  }

  private static boolean isWildcard(final String version) {
    return "*".equals(version) || version.endsWith(".*");
  }

  private static List<VersionCoverageClaim> unresolved(
      final OsvAdvisoryRecord record, final OsvAffectedRange range, final String diagnostic) {
    return List.of(
        VersionCoverageClaim.unresolvedAffected(
            "osv:" + record.osvId() + ":range:" + range.type() + ":" + range.events(), diagnostic));
  }

  /** Accumulates one already ordered range into disjoint Maven intervals. */
  private static final class RangeState {
    /** Advisory whose source identity is retained in diagnostics. */
    private final OsvAdvisoryRecord advisory;

    /** Original range retained for unresolved diagnostics. */
    private final OsvAffectedRange sourceRange;

    /** Successfully normalized affected intervals in sorted event order. */
    private final List<VersionCoverageClaim> claims = new ArrayList<>();

    /** Empty denotes the zero sentinel; otherwise this is the concrete lower bound. */
    private String introduced = "";

    /** Whether an introduced event has opened an interval that still needs a close. */
    private boolean open;

    /** Explains why a malformed event sequence could not be normalized. */
    private String diagnostic;

    private RangeState(final OsvAdvisoryRecord record, final OsvAffectedRange range) {
      this.advisory = record;
      this.sourceRange = range;
    }

    private boolean accept(final Map<String, String> event) {
      final Map.Entry<String, String> field = event.entrySet().iterator().next();
      if (INTRODUCED.equals(field.getKey())) {
        return openInterval(field.getValue());
      }
      if (LIMIT.equals(field.getKey())) {
        diagnostic = "OSV limit event is not a fixed version boundary";
        return false;
      }
      if (FIXED.equals(field.getKey()) || LAST_AFFECTED.equals(field.getKey())) {
        return closeInterval(field.getKey(), field.getValue());
      }
      diagnostic = "Unsupported OSV range event";
      return false;
    }

    private boolean openInterval(final String version) {
      if (open) {
        diagnostic = "OSV introduced event has no closing boundary";
        return false;
      }
      open = true;
      introduced = "0".equals(version) ? "" : version;
      return true;
    }

    private boolean closeInterval(final String event, final String upper) {
      if (!open) {
        diagnostic = "OSV closing event has no open introduced interval";
        return false;
      }
      final boolean inclusive = LAST_AFFECTED.equals(event);
      if (unsupportedBounds(introduced, upper, inclusive)) {
        diagnostic = "OSV range has unsupported or empty version bounds";
        return false;
      }
      final String normalized = rangeText(introduced, upper, inclusive);
      if (!isValidRange(normalized)) {
        diagnostic = "Invalid OSV Maven range boundaries";
        return false;
      }
      claims.add(VersionCoverageClaim.affected(normalized));
      introduced = "";
      open = false;
      return true;
    }

    private boolean unsupportedBounds(
        final String lower, final String upper, final boolean inclusive) {
      return isWildcard(upper)
          || (!lower.isEmpty() && isWildcard(lower))
          || (!lower.isEmpty()
              && compareVersions(lower, upper) >= 0
              && !(inclusive && compareVersions(lower, upper) == 0));
    }

    private String rangeText(final String lower, final String upper, final boolean inclusive) {
      return lower.isEmpty()
          ? "(," + upper + (inclusive ? "]" : ")")
          : "[" + lower + "," + upper + (inclusive ? "]" : ")");
    }

    private boolean isValidRange(final String normalized) {
      try {
        MavenVersionRangeMatcher.validate(normalized);
        return true;
      } catch (final IllegalArgumentException exception) {
        return false;
      }
    }

    private List<VersionCoverageClaim> finish() {
      if (open && !addOpenEnded()) {
        return unresolved(advisory, sourceRange, diagnostic);
      }
      if (claims.isEmpty()) {
        return unresolved(advisory, sourceRange, "OSV range has no supported introduced interval");
      }
      return List.copyOf(claims);
    }

    private boolean addOpenEnded() {
      if (!introduced.isEmpty() && isWildcard(introduced)) {
        diagnostic = "OSV range has an unsupported wildcard version";
        return false;
      }
      final String normalized = introduced.isEmpty() ? "(,)" : "[" + introduced + ",)";
      if (!isValidRange(normalized)) {
        diagnostic = "Invalid OSV Maven range boundaries";
        return false;
      }
      claims.add(VersionCoverageClaim.affected(normalized));
      return true;
    }

    private String failure() {
      return diagnostic;
    }
  }
}
