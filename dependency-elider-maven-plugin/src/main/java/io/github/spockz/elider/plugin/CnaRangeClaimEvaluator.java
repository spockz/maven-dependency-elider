/* WHY: Applies CVE version interval and ordered change semantics for one CNA claim. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.CveVersionClaim;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Matches exact versions and supported Maven ranges in individual CNA claims. */
final class CnaRangeClaimEvaluator {
  /** Required CVE version type for Maven bounds. */
  private static final String MAVEN_VERSION_TYPE = "maven";

  private CnaRangeClaimEvaluator() {}

  /* package */ static MavenRawScopeApplicability.Result matchingClaim(
      final CveVersionClaim claim, final String version) {
    if (!isRange(claim)) {
      return matchingExactClaim(claim, version);
    }
    return matchingRangeClaim(claim, version);
  }

  private static boolean isRange(final CveVersionClaim claim) {
    return claim.lessThan() != null
        || claim.lessThanOrEqual() != null
        || !claim.changes().isEmpty();
  }

  private static MavenRawScopeApplicability.Result matchingExactClaim(
      final CveVersionClaim claim, final String version) {
    if (!version.equals(claim.version())) {
      return null;
    }
    if (claim.versionType() != null && !MAVEN_VERSION_TYPE.equalsIgnoreCase(claim.versionType())) {
      return MavenRawScopeApplicability.unknown(
          "Exact CNA version uses an unsupported versionType");
    }
    return CnaClaimStatusMapper.map(claim.status(), "Exact CNA version claim");
  }

  private static MavenRawScopeApplicability.Result matchingRangeClaim(
      final CveVersionClaim claim, final String version) {
    if (!hasSupportedBound(claim)) {
      return MavenRawScopeApplicability.unknown(
          "CNA range requires Maven versionType and one upper bound");
    }
    final String upper = upperBound(claim);
    final boolean inclusiveUpper = claim.lessThanOrEqual() != null;
    final String interval = interval(claim.version(), upper, inclusiveUpper);
    if (!matchesInterval(interval, version)) {
      return null;
    }
    return statusAfterChanges(claim, version, upper, inclusiveUpper);
  }

  private static MavenRawScopeApplicability.Result statusAfterChanges(
      final CveVersionClaim claim,
      final String version,
      final String upper,
      final boolean inclusiveUpper) {
    final Optional<List<Map<String, String>>> checkedChanges =
        CnaRangeChangeValidator.validatedChanges(claim, upper, inclusiveUpper);
    if (checkedChanges.isEmpty()) {
      return MavenRawScopeApplicability.unknown(
          "CNA changes are malformed, duplicated, or outside their version range");
    }
    String status = claim.status();
    for (final Map<String, String> change : checkedChanges.orElseThrow()) {
      if (CnaRangeChangeValidator.appliesAtOrBefore(change.get("at"), version)) {
        status = change.get("status");
      }
    }
    return CnaClaimStatusMapper.map(status, "Matching CNA range claim");
  }

  private static boolean matchesInterval(final String interval, final String version) {
    try {
      MavenVersionRangeMatcher.validate(interval);
      return MavenVersionRangeMatcher.includes(interval, version);
    } catch (final IllegalArgumentException exception) {
      return false;
    }
  }

  private static boolean hasSupportedBound(final CveVersionClaim claim) {
    return MAVEN_VERSION_TYPE.equalsIgnoreCase(claim.versionType())
        && (claim.lessThan() == null) != (claim.lessThanOrEqual() == null);
  }

  /* package */ static String upperBound(final CveVersionClaim claim) {
    return claim.lessThan() == null ? claim.lessThanOrEqual() : claim.lessThan();
  }

  /* package */ static String interval(
      final String lower, final String upper, final boolean inclusiveUpper) {
    return "[" + lower + "," + upper + (inclusiveUpper ? "]" : ")");
  }
}
