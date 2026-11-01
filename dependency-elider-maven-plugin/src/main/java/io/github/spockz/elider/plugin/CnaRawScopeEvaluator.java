/* WHY: Evaluates raw CNA exact, default, and Maven range claims independently. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveVersionClaim;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Selects one unambiguous raw CNA version decision for a concrete Maven version. */
final class CnaRawScopeEvaluator {
  /** Exactly one matching raw claim is required for a positive decision. */
  private static final int SINGLE_MATCH = 1;

  private CnaRawScopeEvaluator() {}

  /* package */ static MavenRawScopeApplicability.Result evaluate(
      final CveAffectedEntryContext entry, final String version) {
    Objects.requireNonNull(entry, "entry");
    if (!MavenRawScopeApplicability.validVersion(version)) {
      return MavenRawScopeApplicability.unknown("Candidate Maven version is invalid");
    }
    final MavenRawScopeApplicability.Result validation =
        CnaClaimSetValidator.validate(entry.versions());
    if (validation != null) {
      return validation;
    }
    final List<MavenRawScopeApplicability.Result> matchingClaims = new ArrayList<>();
    for (final CveVersionClaim claim : entry.versions()) {
      final MavenRawScopeApplicability.Result matching =
          CnaRangeClaimEvaluator.matchingClaim(claim, version);
      if (matching == null) {
        continue;
      }
      if (matching.status() == MavenRawScopeApplicability.Status.UNKNOWN) {
        return matching;
      }
      matchingClaims.add(matching);
    }
    if (matchingClaims.size() > SINGLE_MATCH) {
      return MavenRawScopeApplicability.unknown(
          "Multiple CNA version claims apply to the candidate version");
    }
    if (!matchingClaims.isEmpty()) {
      return matchingClaims.getFirst();
    }
    return entry.defaultStatus() == null
        ? MavenRawScopeApplicability.unknown(
            "CNA entry has no matching version and no defaultStatus")
        : CnaClaimStatusMapper.map(entry.defaultStatus(), "CNA defaultStatus");
  }
}
