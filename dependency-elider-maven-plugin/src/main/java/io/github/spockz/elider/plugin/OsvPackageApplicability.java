// WHY: Reports exact OSV package applicability without flattening unsupported ranges.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import java.util.List;
import java.util.Map;

/** Evaluates only exact versions and one supported Maven ecosystem interval. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class OsvPackageApplicability {
  /** Number of interval events in a one-bound claim. */
  private static final int ONE_EVENT = 1;

  /** A supported bounded interval has one start and one end event. */
  private static final int TWO_EVENTS = 2;

  /** Number of keys in one boundary event. */
  private static final int ONE_FIELD = 1;

  /** OSV event name for the first affected version. */
  private static final String INTRODUCED = "introduced";

  /** OSV event name for the first fixed version. */
  private static final String FIXED = "fixed";

  /** OSV event name for the last affected version. */
  private static final String LAST_AFFECTED = "last_affected";

  /** Reportable applicability outcomes. */
  enum Status {
    /** Exact data establishes the candidate version is affected. */
    APPLICABLE,
    /** Exact data or one supported interval establishes the version is outside scope. */
    NOT_APPLICABLE,
    /** The preserved claim does not support a safe version conclusion. */
    UNRESOLVED
  }

  /** Applicability result and concise reason for the saved report. */
  record Result(Status status, String rationale) {}

  private OsvPackageApplicability() {}

  static Result evaluate(final OsvAffectedPackage affectedPackage, final String version) {
    return evaluateClaims(affectedPackage.versions(), affectedPackage.ranges(), version);
  }

  static Result evaluateClaims(
      final List<String> affectedVersions,
      final List<OsvAffectedRange> ranges,
      final String version) {
    if (affectedVersions.contains(version)) {
      return new Result(Status.APPLICABLE, "Exact version is listed by the OSV affected package");
    }
    if (ranges.size() > 1
        || ranges.stream().anyMatch(range -> !"ECOSYSTEM".equalsIgnoreCase(range.type()))) {
      return unresolved("OSV ranges are multiple or unsupported for Maven applicability");
    }
    if (ranges.isEmpty()) {
      return affectedVersions.isEmpty()
          ? unresolved("OSV package has no versions or ranges")
          : new Result(Status.NOT_APPLICABLE, "Exact version is not listed by OSV");
    }
    final OsvAffectedRange range = ranges.getFirst();
    final String specification = singleInterval(range.events());
    if (specification == null) {
      return unresolved("OSV range events are not one supported contiguous interval");
    }
    try {
      return MavenVersionRangeMatcher.includes(specification, version)
          ? new Result(Status.APPLICABLE, "Maven version is inside the preserved OSV interval")
          : new Result(
              Status.NOT_APPLICABLE, "Maven version is outside the preserved OSV interval");
    } catch (final IllegalArgumentException exception) {
      return unresolved("OSV interval cannot be evaluated with Maven version semantics");
    }
  }

  private static Result unresolved(final String rationale) {
    return new Result(Status.UNRESOLVED, rationale);
  }

  private static String singleInterval(final List<Map<String, String>> events) {
    if (events.isEmpty() || events.size() > TWO_EVENTS) {
      return null;
    }
    final Map<String, String> first = events.getFirst();
    if (!first.keySet().equals(java.util.Set.of(INTRODUCED))) {
      return null;
    }
    final String introduced = first.get(INTRODUCED);
    if (introduced == null || introduced.isBlank()) {
      return null;
    }
    if (events.size() == ONE_EVENT) {
      return unboundedInterval(introduced);
    }
    return boundedInterval(events.get(ONE_EVENT), introduced);
  }

  private static String unboundedInterval(final String introduced) {
    return "0".equals(introduced) ? null : "[" + introduced + ",)";
  }

  private static String boundedInterval(final Map<String, String> last, final String introduced) {
    if (last.size() != ONE_FIELD) {
      return null;
    }
    final Map.Entry<String, String> boundEntry = last.entrySet().iterator().next();
    final String boundName = boundEntry.getKey();
    if (!FIXED.equals(boundName) && !LAST_AFFECTED.equals(boundName)) {
      return null;
    }
    final String bound = boundEntry.getValue();
    if (bound == null || bound.isBlank()) {
      return null;
    }
    final boolean openStart = "0".equals(introduced);
    final String lower = openStart ? "(" : "[" + introduced;
    final String upper = FIXED.equals(boundName) ? ")" : "]";
    return lower + "," + bound + upper;
  }
}
