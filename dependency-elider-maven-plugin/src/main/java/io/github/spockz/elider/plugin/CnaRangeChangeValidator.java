/* WHY: Validates ordered CNA status changes against their declared Maven interval. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.CveVersionClaim;
import java.util.Map;
import java.util.Set;
import org.apache.maven.artifact.versioning.ComparableVersion;

/** Validates CNA range changes before they can affect a concrete version decision. */
final class CnaRangeChangeValidator {
  private CnaRangeChangeValidator() {}

  /* package */ static MavenRawScopeApplicability.Result validate(
      final CveVersionClaim claim, final String upper, final boolean inclusiveUpper) {
    String previousChange = null;
    for (final Map<String, String> change : claim.changes()) {
      final MavenRawScopeApplicability.Result validation =
          validateOneChange(change, claim.version(), upper, previousChange, inclusiveUpper);
      if (validation != null) {
        return validation;
      }
      previousChange = change.get("at");
    }
    return null;
  }

  /* package */ static boolean appliesAtOrBefore(final String change, final String candidate) {
    return new ComparableVersion(change).compareTo(new ComparableVersion(candidate)) <= 0;
  }

  private static MavenRawScopeApplicability.Result validateOneChange(
      final Map<String, String> change,
      final String lowerVersion,
      final String upperVersion,
      final String previousChange,
      final boolean inclusiveUpper) {
    final String changeVersion = change.get("at");
    if (!change.keySet().equals(Set.of("at", "status"))
        || !MavenRawScopeApplicability.validVersion(changeVersion)) {
      return MavenRawScopeApplicability.unknown(
          "CNA change has malformed fields or an invalid version");
    }
    if (!isWithinRange(changeVersion, lowerVersion, upperVersion, previousChange, inclusiveUpper)) {
      return MavenRawScopeApplicability.unknown(
          "CNA changes are unordered or outside their version range");
    }
    return CnaClaimStatusMapper.isKnown(change.get("status"))
        ? null
        : MavenRawScopeApplicability.unknown("CNA change status is unsupported");
  }

  private static boolean isWithinRange(
      final String current,
      final String lower,
      final String upper,
      final String previous,
      final boolean inclusiveUpper) {
    final ComparableVersion currentVersion = new ComparableVersion(current);
    final int upperComparison = currentVersion.compareTo(new ComparableVersion(upper));
    return (previous == null || currentVersion.compareTo(new ComparableVersion(previous)) > 0)
        && currentVersion.compareTo(new ComparableVersion(lower)) >= 0
        && (inclusiveUpper ? upperComparison <= 0 : upperComparison < 0);
  }
}
