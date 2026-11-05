/* WHY: Keeps saved proof rows from asserting outcomes their captured evidence cannot support. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.CodeAttributionResolver;
import io.github.spockz.elider.model.CodeClaim;
import io.github.spockz.elider.model.VersionApplicability;
import java.io.IOException;
import java.util.List;

/** Checks the internal evidence needed to persist a verified proof outcome. */
final class MavenElisionReportProofValidator {
  private MavenElisionReportProofValidator() {}

  /* package */ static void validate(final GenericFindingAssessment finding) throws IOException {
    if (!isProof(finding.outcome())) {
      return;
    }
    if (!isAutomaticallyVerifiable(finding)) {
      throw new IOException(
          "Saved proof requires affected applicability and automatic verification");
    }
    validateRequiredEvidence(finding);
  }

  private static boolean isProof(final GenericFindingAssessment.Outcome outcome) {
    return outcome == GenericFindingAssessment.Outcome.DECLARED_CODE_ABSENT
        || outcome == GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT;
  }

  private static boolean isAutomaticallyVerifiable(final GenericFindingAssessment finding) {
    return finding.applicability() == VersionApplicability.AFFECTED
        && finding.intent().orElse(null) == AssessmentIntent.AUTO_VERIFY;
  }

  private static void validateRequiredEvidence(final GenericFindingAssessment finding)
      throws IOException {
    if (finding.outcome() == GenericFindingAssessment.Outcome.DECLARED_CODE_ABSENT) {
      validateDeclaredCode(finding);
    } else {
      validatePrerequisites(finding);
    }
  }

  private static void validateDeclaredCode(final GenericFindingAssessment finding)
      throws IOException {
    final List<CodeAttributionResolver.DeclarationResult> declared =
        finding.codeAttribution().stream()
            .filter(value -> value.claim().kind() == CodeClaim.Kind.DECLARED)
            .toList();
    if (finding.codeGroupStatus() != ClaimGroupStatus.DECLARED
        || declared.isEmpty()
        || declared.stream()
            .anyMatch(value -> value.status() != CodeAttributionResolver.Status.RESOLVED)) {
      throw new IOException("Saved code proof requires resolved declared code");
    }
  }

  private static void validatePrerequisites(final GenericFindingAssessment finding)
      throws IOException {
    if (finding.prerequisiteGroupStatus() != ClaimGroupStatus.DECLARED
        || finding.effectivePrerequisites().isEmpty()) {
      throw new IOException("Saved prerequisite proof requires declared prerequisite pairs");
    }
  }
}
