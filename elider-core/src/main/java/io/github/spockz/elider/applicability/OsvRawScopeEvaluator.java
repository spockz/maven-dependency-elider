/* WHY: Evaluates OSV versions and ranges without relying on flattened display ranges. */

package io.github.spockz.elider.applicability;

import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import java.util.List;
import java.util.Objects;

/** Applies the supported OSV affected-version union semantics. */
final class OsvRawScopeEvaluator {
  private OsvRawScopeEvaluator() {}

  /** Evaluates one typed raw OSV package. */
  /* package */ static MavenRawScopeApplicability.Result evaluate(
      final OsvAffectedPackage affectedPackage, final String version) {
    Objects.requireNonNull(affectedPackage, "affectedPackage");
    return evaluateClaims(
        affectedPackage.ecosystem(), affectedPackage.versions(), affectedPackage.ranges(), version);
  }

  /* package */ static MavenRawScopeApplicability.Result evaluateClaims(
      final String ecosystem,
      final List<String> versions,
      final List<OsvAffectedRange> ranges,
      final String version) {
    if (!MavenRawScopeApplicability.isMavenEcosystem(ecosystem)) {
      return MavenRawScopeApplicability.unknown("OSV package ecosystem is not Maven");
    }
    if (!MavenRawScopeApplicability.validVersion(version)) {
      return MavenRawScopeApplicability.unknown("Candidate Maven version is invalid");
    }
    if (versions.contains(version)) {
      return MavenRawScopeApplicability.affected(
          "Exact version is listed in the OSV affected package");
    }
    if (ranges.isEmpty()) {
      return versions.isEmpty()
          ? MavenRawScopeApplicability.unknown("OSV package has no exact versions or ranges")
          : MavenRawScopeApplicability.unaffected("Exact version is not listed by OSV");
    }
    boolean anyAffected = false;
    for (final OsvAffectedRange range : ranges) {
      final MavenRawScopeApplicability.Result result = OsvRangeEvaluator.evaluate(range, version);
      if (result.status() == MavenRawScopeApplicability.Status.UNKNOWN) {
        return result;
      }
      anyAffected |= result.status() == MavenRawScopeApplicability.Status.AFFECTED;
    }
    return anyAffected
        ? MavenRawScopeApplicability.affected("Candidate is inside a supported raw OSV range")
        : MavenRawScopeApplicability.unaffected(
            "Candidate is outside every supported raw OSV range");
  }
}
