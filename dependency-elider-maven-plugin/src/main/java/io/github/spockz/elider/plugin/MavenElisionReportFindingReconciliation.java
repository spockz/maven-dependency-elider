// WHY: Replays a saved canonical alias class while validating component-local contributions.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.GenericFindingReconciler;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;

/** WHY: Saved reports must replay canonical findings against component evidence. */
final class MavenElisionReportFindingReconciliation {
  private MavenElisionReportFindingReconciliation() {}

  /** Shared by report validators to enforce one canonical contribution replay. */
  /* default */ static GenericVulnerabilityFinding requireCanonicalFinding(
      final GenericFindingAssessment saved, final String evidenceField) throws IOException {
    if (saved.contributions().isEmpty()) {
      throw new IOException(evidenceField + " has no component contributions");
    }
    if (saved.contributions().stream().anyMatch(value -> !sameComponent(value, saved))) {
      throw new IOException(evidenceField + " contribution component differs from saved GATC");
    }
    try {
      final GenericVulnerabilityFinding canonical =
          GenericFindingReconciler.reconcileResolvedIdentity(
              saved.contributions(), saved.aliases());
      if (!canonical.vulnerabilityId().equals(saved.vulnerabilityId())) {
        throw new IOException(evidenceField + " canonical vulnerability does not match saved row");
      }
      return canonical;
    } catch (final IllegalArgumentException exception) {
      throw new IOException(
          evidenceField + " identity does not match saved alias class: " + exception.getMessage(),
          exception);
    }
  }

  /** WHY: Contributions must stay within the saved row's component. */
  private static boolean sameComponent(
      final VulnerabilityFindingContribution contribution, final GenericFindingAssessment saved) {
    final ArtifactCoordinate candidate = saved.candidate();
    return contribution.groupId().equals(candidate.groupId())
        && contribution.artifactId().equals(candidate.artifactId())
        && contribution.type().equals(candidate.type())
        && contribution.classifier().equals(candidate.classifier());
  }
}
