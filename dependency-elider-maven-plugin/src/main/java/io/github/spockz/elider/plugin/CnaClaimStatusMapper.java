/* WHY: Maps supported CNA status strings to the shared applicability result. */

package io.github.spockz.elider.plugin;

/** Recognizes the CVE status vocabulary used by the raw applicability evaluator. */
final class CnaClaimStatusMapper {
  /** CVE status that indicates an affected version. */
  private static final String AFFECTED = "affected";

  /** CVE status that indicates an unaffected version. */
  private static final String UNAFFECTED = "unaffected";

  /** CVE status that does not establish applicability. */
  private static final String UNKNOWN = "unknown";

  private CnaClaimStatusMapper() {}

  /* package */ static boolean isKnown(final String status) {
    return AFFECTED.equalsIgnoreCase(status)
        || UNAFFECTED.equalsIgnoreCase(status)
        || UNKNOWN.equalsIgnoreCase(status);
  }

  /* package */ static MavenRawScopeApplicability.Result map(
      final String status, final String rationale) {
    if (AFFECTED.equalsIgnoreCase(status)) {
      return MavenRawScopeApplicability.affected(rationale);
    }
    if (UNAFFECTED.equalsIgnoreCase(status)) {
      return MavenRawScopeApplicability.unaffected(rationale);
    }
    return MavenRawScopeApplicability.unknown("CNA status is unknown or unsupported");
  }
}
