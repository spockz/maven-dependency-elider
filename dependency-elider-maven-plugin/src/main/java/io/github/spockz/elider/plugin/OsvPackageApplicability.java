// WHY: Reports exact OSV package applicability without flattening unsupported ranges.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.applicability.MavenRawScopeApplicability;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import java.util.List;

/** Projects raw OSV decisions into report statuses. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class OsvPackageApplicability {
  /** Reportable applicability outcomes. */
  enum Status {
    /** Exact data establishes the candidate version is affected. */
    APPLICABLE,
    /** Exact data or all supported intervals establish the version is outside scope. */
    NOT_APPLICABLE,
    /** The preserved claim does not support a safe version conclusion. */
    UNRESOLVED
  }

  /** Applicability result and concise reason for the saved report. */
  record Result(Status status, String rationale) {}

  private OsvPackageApplicability() {}

  static Result evaluate(final OsvAffectedPackage affectedPackage, final String version) {
    return reportResult(MavenRawScopeApplicability.evaluateOsv(affectedPackage, version));
  }

  static Result evaluateClaims(
      final List<String> affectedVersions,
      final List<OsvAffectedRange> ranges,
      final String version) {
    return reportResult(
        MavenRawScopeApplicability.evaluateOsvClaims("Maven", affectedVersions, ranges, version));
  }

  private static Result reportResult(final MavenRawScopeApplicability.Result result) {
    final Status status =
        switch (result.status()) {
          case AFFECTED -> Status.APPLICABLE;
          case UNAFFECTED -> Status.NOT_APPLICABLE;
          case UNKNOWN -> Status.UNRESOLVED;
        };
    return new Result(status, result.rationale());
  }
}
