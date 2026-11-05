/* WHY: Applies one semantic admission policy before either physical proof engine. */

package io.github.spockz.elider.model;

import java.util.Objects;

/** Common exact-candidate and review-policy checks without provider authority. */
final class FindingVerification {
  private FindingVerification() {}

  @SuppressWarnings("PMD.CyclomaticComplexity")
  /* package */ static void requireEligible(
      final GenericVulnerabilityFinding finding, final ArtifactCoordinate candidate) {
    Objects.requireNonNull(finding, "finding");
    Objects.requireNonNull(candidate, "candidate");
    final VulnerabilityFindingContribution component = finding.contributions().getFirst();
    if (!component.groupId().equals(candidate.groupId())
        || !component.artifactId().equals(candidate.artifactId())
        || !component.type().equals(candidate.type())
        || !component.classifier().equals(candidate.classifier())) {
      throw new IllegalArgumentException("Finding component does not match exact candidate");
    }
    if (candidate.version() == null
        || candidate.version().isBlank()
        || finding.applicability(candidate.version()) != VersionApplicability.AFFECTED) {
      throw new IllegalArgumentException("Finding requires a supported affected exact version");
    }
    if (finding.intentFor(candidate.version()).orElse(AssessmentIntent.REVIEW_ONLY)
        != AssessmentIntent.AUTO_VERIFY) {
      throw new IllegalArgumentException("Finding requires review before physical proof");
    }
  }
}
