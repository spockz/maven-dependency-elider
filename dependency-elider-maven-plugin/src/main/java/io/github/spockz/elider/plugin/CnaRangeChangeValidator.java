/* WHY: Validates and orders CNA status changes against their declared Maven interval. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.CveVersionClaim;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.artifact.versioning.ComparableVersion;

/** Validates CNA range changes before they can affect a concrete version decision. */
final class CnaRangeChangeValidator {
  private CnaRangeChangeValidator() {}

  /* package */ static Optional<List<Map<String, String>>> validatedChanges(
      final CveVersionClaim claim, final String upper, final boolean inclusiveUpper) {
    final List<Map<String, String>> changes = claim.changes();
    for (final Map<String, String> change : changes) {
      final MavenRawScopeApplicability.Result validation =
          validateOneChange(change, claim.version(), upper, inclusiveUpper);
      if (validation != null) {
        return Optional.empty();
      }
    }
    final List<VersionedChange> ordered =
        changes.stream()
            .map(change -> new VersionedChange(change, new ComparableVersion(change.get("at"))))
            .sorted(Comparator.comparing(VersionedChange::version))
            .toList();
    ComparableVersion previousVersion = null;
    for (final VersionedChange change : ordered) {
      if (previousVersion != null && previousVersion.compareTo(change.version()) == 0) {
        return Optional.empty();
      }
      previousVersion = change.version();
    }
    return Optional.of(ordered.stream().map(VersionedChange::claim).toList());
  }

  /* package */ static boolean appliesAtOrBefore(final String change, final String candidate) {
    return new ComparableVersion(change).compareTo(new ComparableVersion(candidate)) <= 0;
  }

  private static MavenRawScopeApplicability.Result validateOneChange(
      final Map<String, String> change,
      final String lowerVersion,
      final String upperVersion,
      final boolean inclusiveUpper) {
    final String changeVersion = change.get("at");
    if (!change.keySet().equals(Set.of("at", "status"))
        || !MavenRawScopeApplicability.validVersion(changeVersion)) {
      return MavenRawScopeApplicability.unknown(
          "CNA change has malformed fields or an invalid version");
    }
    if (!isWithinRange(changeVersion, lowerVersion, upperVersion, inclusiveUpper)) {
      return MavenRawScopeApplicability.unknown(
          "CNA changes are unordered or outside their version range");
    }
    return CnaClaimStatusMapper.isKnown(change.get("status"))
        ? null
        : MavenRawScopeApplicability.unknown("CNA change status is unsupported");
  }

  private static boolean isWithinRange(
      final String current, final String lower, final String upper, final boolean inclusiveUpper) {
    final ComparableVersion currentVersion = new ComparableVersion(current);
    final int upperComparison = currentVersion.compareTo(new ComparableVersion(upper));
    return currentVersion.compareTo(new ComparableVersion(lower)) >= 0
        && (inclusiveUpper ? upperComparison <= 0 : upperComparison < 0);
  }

  private record VersionedChange(Map<String, String> claim, ComparableVersion version) {}
}
