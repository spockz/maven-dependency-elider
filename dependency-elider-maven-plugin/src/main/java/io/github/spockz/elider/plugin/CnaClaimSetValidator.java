/* WHY: Rejects malformed and overlapping CNA claims before a candidate is selected. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.CveVersionClaim;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.maven.artifact.versioning.ComparableVersion;

/** Validates claim set boundaries and status values for one CNA product entry. */
final class CnaClaimSetValidator {
  private CnaClaimSetValidator() {}

  /* package */ static MavenRawScopeApplicability.Result validate(
      final List<CveVersionClaim> claims) {
    final List<CnaClaimInterval> intervals = new ArrayList<>();
    for (final CveVersionClaim claim : claims) {
      final MavenRawScopeApplicability.Result validation = validateClaim(claim, intervals);
      if (validation != null) {
        return validation;
      }
    }
    return hasOverlappingClaims(intervals)
        ? MavenRawScopeApplicability.unknown("CNA version claims overlap or conflict")
        : null;
  }

  private static MavenRawScopeApplicability.Result validateClaim(
      final CveVersionClaim claim, final List<CnaClaimInterval> intervals) {
    if (!MavenRawScopeApplicability.validVersion(claim.version())
        || (claim.versionType() != null && !"maven".equalsIgnoreCase(claim.versionType()))) {
      return MavenRawScopeApplicability.unknown(
          "CNA claim uses an invalid version or unsupported versionType");
    }
    if (!CnaClaimStatusMapper.isKnown(claim.status())) {
      return MavenRawScopeApplicability.unknown("CNA claim status is unsupported");
    }
    if (!isRange(claim)) {
      intervals.add(new CnaClaimInterval(claim.version(), claim.version(), true));
      return null;
    }
    return validateRangeClaim(claim, intervals);
  }

  private static MavenRawScopeApplicability.Result validateRangeClaim(
      final CveVersionClaim claim, final List<CnaClaimInterval> intervals) {
    if (!"maven".equalsIgnoreCase(claim.versionType())
        || (claim.lessThan() == null) == (claim.lessThanOrEqual() == null)) {
      return MavenRawScopeApplicability.unknown(
          "CNA range requires Maven versionType and one upper bound");
    }
    final String upper = CnaRangeClaimEvaluator.upperBound(claim);
    final boolean inclusiveUpper = claim.lessThanOrEqual() != null;
    final String specification =
        CnaRangeClaimEvaluator.interval(claim.version(), upper, inclusiveUpper);
    if (!validMavenRange(claim.version(), upper, inclusiveUpper, specification)) {
      return MavenRawScopeApplicability.unknown(
          "CNA range cannot be evaluated with Maven semantics");
    }
    final Optional<List<java.util.Map<String, String>>> changes =
        CnaRangeChangeValidator.validatedChanges(claim, upper, inclusiveUpper);
    if (changes.isEmpty()) {
      return MavenRawScopeApplicability.unknown(
          "CNA changes are malformed, duplicated, or outside their version range");
    }
    intervals.add(new CnaClaimInterval(claim.version(), upper, inclusiveUpper));
    return null;
  }

  private static boolean validMavenRange(
      final String lower,
      final String upper,
      final boolean inclusiveUpper,
      final String specification) {
    final int comparison = new ComparableVersion(lower).compareTo(new ComparableVersion(upper));
    if (comparison > 0 || (comparison == 0 && !inclusiveUpper)) {
      return false;
    }
    try {
      MavenVersionRangeMatcher.validate(specification);
      return true;
    } catch (final IllegalArgumentException exception) {
      return false;
    }
  }

  private static boolean hasOverlappingClaims(final List<CnaClaimInterval> intervals) {
    for (int first = 0; first < intervals.size(); first++) {
      for (int second = first + 1; second < intervals.size(); second++) {
        if (overlaps(intervals.get(first), intervals.get(second))) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean overlaps(final CnaClaimInterval left, final CnaClaimInterval right) {
    final ComparableVersion leftStart = new ComparableVersion(left.lower());
    final ComparableVersion leftEnd = new ComparableVersion(left.upper());
    final ComparableVersion rightStart = new ComparableVersion(right.lower());
    final ComparableVersion rightEnd = new ComparableVersion(right.upper());
    final int leftEndToRightStart = leftEnd.compareTo(rightStart);
    final int rightEndToLeftStart = rightEnd.compareTo(leftStart);
    final boolean leftBeforeRight =
        leftEndToRightStart < 0 || (leftEndToRightStart == 0 && !left.upperInclusive());
    final boolean rightBeforeLeft =
        rightEndToLeftStart < 0 || (rightEndToLeftStart == 0 && !right.upperInclusive());
    return !leftBeforeRight && !rightBeforeLeft;
  }

  private static boolean isRange(final CveVersionClaim claim) {
    return claim.lessThan() != null
        || claim.lessThanOrEqual() != null
        || !claim.changes().isEmpty();
  }

  private record CnaClaimInterval(String lower, String upper, boolean upperInclusive) {}
}
