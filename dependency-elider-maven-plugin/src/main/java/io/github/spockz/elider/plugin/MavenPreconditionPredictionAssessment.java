/* WHY: Applies non-authoritative prerequisite forecasts to selected findings. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.VersionApplicability;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MavenPreconditionPredictionAssessment {
  private MavenPreconditionPredictionAssessment() {}

  static MavenPreconditionPrediction.Capture captureIfSelected(
      final MavenPreconditionPrediction.CaptureSupplier supplier,
      final Map<ArtifactCoordinate, List<GenericVulnerabilityFinding>> findingsByCandidate)
      throws IOException {
    if (supplier == null || !hasSelectedPrerequisites(findingsByCandidate)) {
      return null;
    }
    return supplier.capture();
  }

  private static boolean hasSelectedPrerequisites(
      final Map<ArtifactCoordinate, List<GenericVulnerabilityFinding>> findingsByCandidate) {
    for (final Map.Entry<ArtifactCoordinate, List<GenericVulnerabilityFinding>> entry :
        findingsByCandidate.entrySet()) {
      for (final GenericVulnerabilityFinding finding : entry.getValue()) {
        final String version = entry.getKey().version();
        if (finding.prerequisiteGroupStatusFor(version) == ClaimGroupStatus.DECLARED
            && !finding.effectivePrerequisiteGroupsFor(version).isEmpty()) {
          return true;
        }
      }
    }
    return false;
  }

  static boolean plannedAbsence(
      final Optional<PrerequisitePrediction> prediction,
      final VersionApplicability applicability,
      final Optional<AssessmentIntent> intent,
      final GenericFindingAssessment.Outcome currentOutcome) {
    if (prediction.isEmpty()
        || applicability != VersionApplicability.AFFECTED
        || intent.orElse(null) != AssessmentIntent.AUTO_VERIFY
        || currentOutcome != GenericFindingAssessment.Outcome.NO_PROOF) {
      return false;
    }
    final List<PrerequisitePrediction.GroupForecast> groups = prediction.orElseThrow().groups();
    return !groups.isEmpty()
        && groups.stream().allMatch(PrerequisitePrediction.GroupForecast::disarmed)
        && groups.stream().anyMatch(group -> !alreadyDisarmed(group));
  }

  private static boolean alreadyDisarmed(final PrerequisitePrediction.GroupForecast group) {
    return switch (group.group().operator()) {
      case ANY_OF ->
          group.members().stream()
              .allMatch(
                  member -> member.reason() == PrerequisitePrediction.MemberReason.ALREADY_ABSENT);
      case ALL_OF ->
          group.members().stream()
              .anyMatch(
                  member -> member.reason() == PrerequisitePrediction.MemberReason.ALREADY_ABSENT);
    };
  }
}
