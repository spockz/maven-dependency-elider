/* WHY: Keeps forecast validation separate from physical proof validation. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.PrerequisiteGroup;
import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MavenElisionReportPredictionValidator {
  private MavenElisionReportPredictionValidator() {}

  static void validatePrediction(
      final GenericFindingAssessment finding, final MavenElisionReportSnapshot snapshot)
      throws IOException {
    final PrerequisitePrediction prediction = finding.prerequisitePrediction().orElse(null);
    requirePredictionForOutcome(finding, prediction);
    if (prediction == null) {
      return;
    }
    requireAnalysisMode(snapshot);
    requireCandidateMatch(finding, prediction);
    final GenericVulnerabilityFinding merged = mergeContributions(finding);
    requireSelectedGroups(finding, prediction, merged);
    requireSelectedProjection(finding, merged);
    validateProviderPlans(prediction, snapshot);
    requirePlannedAbsence(finding, prediction);
  }

  private static void requirePredictionForOutcome(
      final GenericFindingAssessment finding, final PrerequisitePrediction prediction)
      throws IOException {
    if (prediction == null
        && finding.outcome() == GenericFindingAssessment.Outcome.PLANNED_PREREQUISITES_ABSENT) {
      throw new IOException("Planned prerequisite absence requires prediction evidence");
    }
  }

  private static void requireAnalysisMode(final MavenElisionReportSnapshot snapshot)
      throws IOException {
    if (snapshot != null && snapshot.mode() != MavenElisionReportSnapshot.Mode.ANALYSIS) {
      throw new IOException("Applied report cannot contain prerequisite prediction evidence");
    }
  }

  private static void requireCandidateMatch(
      final GenericFindingAssessment finding, final PrerequisitePrediction prediction)
      throws IOException {
    if (!prediction.candidate().equals(finding.candidate())) {
      throw new IOException("prerequisitePrediction.candidate does not match finding candidate");
    }
  }

  private static GenericVulnerabilityFinding mergeContributions(
      final GenericFindingAssessment finding) throws IOException {
    try {
      return GenericVulnerabilityFinding.merge(finding.contributions());
    } catch (final IllegalArgumentException exception) {
      throw new IOException("prerequisitePrediction cannot be matched to source groups", exception);
    }
  }

  private static void requireSelectedGroups(
      final GenericFindingAssessment finding,
      final PrerequisitePrediction prediction,
      final GenericVulnerabilityFinding merged)
      throws IOException {
    final Set<PrerequisiteGroup> selected =
        Set.copyOf(merged.effectivePrerequisiteGroupsFor(finding.candidate().version()));
    final Set<PrerequisiteGroup> predicted =
        prediction.groups().stream()
            .map(PrerequisitePrediction.GroupForecast::group)
            .collect(Collectors.toSet());
    if (!predicted.equals(selected)) {
      throw new IOException("prerequisitePrediction.groups differ from selected source groups");
    }
  }

  private static void requireSelectedProjection(
      final GenericFindingAssessment finding, final GenericVulnerabilityFinding merged)
      throws IOException {
    final String version = finding.candidate().version();
    if (finding.prerequisiteGroupStatus() != ClaimGroupStatus.DECLARED
        || merged.prerequisiteGroupStatusFor(version) != ClaimGroupStatus.DECLARED) {
      throw new IOException("prerequisitePrediction requires DECLARED prerequisite groups");
    }
    if (finding.prerequisiteGroupStatus() != merged.prerequisiteGroupStatusFor(version)) {
      throw new IOException("prerequisitePrediction status differs from selected contributions");
    }
    if (!Set.copyOf(merged.effectivePrerequisitesFor(version))
        .equals(Set.copyOf(finding.effectivePrerequisites()))) {
      throw new IOException(
          "effective prerequisites differ from the selected contribution projection");
    }
  }

  private static void validateProviderPlans(
      final PrerequisitePrediction prediction, final MavenElisionReportSnapshot snapshot)
      throws IOException {
    if (snapshot == null) {
      return;
    }
    final Set<String> droppedIds =
        snapshot.droppedArtifacts().stream()
            .map(
                dropped ->
                    MavenElisionReportSourceCoordinateValidator.parseCanonical(dropped.coordinate())
                        .toId())
            .collect(Collectors.toSet());
    for (final PrerequisitePrediction.GroupForecast group : prediction.groups()) {
      for (final PrerequisitePrediction.MemberForecast member : group.members()) {
        for (final PrerequisitePrediction.ProviderForecast provider : member.providers()) {
          validateProviderPlan(provider, member.claim().requiresClass(), snapshot, droppedIds);
        }
      }
    }
  }

  private static void validateProviderPlan(
      final PrerequisitePrediction.ProviderForecast provider,
      final String requiredClass,
      final MavenElisionReportSnapshot snapshot,
      final Set<String> droppedIds)
      throws IOException {
    if (provider.kind()
        != io.github.spockz.elider.model.PreconditionClassInventory.ProviderKind
            .DEPENDENCY_ARCHIVE) {
      return;
    }
    final String coordinateId = provider.coordinate().toId();
    final MavenElisionReportSnapshot.TrimmedArtifact trim =
        snapshot.trimmedArtifacts().stream()
            .filter(
                row ->
                    MavenElisionReportSourceCoordinateValidator.parseCanonical(row.coordinate())
                        .toId()
                        .equals(coordinateId))
            .findFirst()
            .orElse(null);
    final boolean dropped = droppedIds.contains(coordinateId);
    final boolean removed = trim != null && trim.plannedClasses().contains(requiredClass);
    final boolean agrees =
        switch (provider.plan()) {
          case ELIDED -> dropped && trim == null;
          case TRIMMED_CLASS -> !dropped && removed;
          case RETAINED -> !dropped && !removed;
        };
    if (!agrees) {
      throw new IOException(
          "prerequisitePrediction provider plan contradicts ANALYSIS output rows for "
              + coordinateId
              + " and "
              + requiredClass);
    }
  }

  private static void requirePlannedAbsence(
      final GenericFindingAssessment finding, final PrerequisitePrediction prediction)
      throws IOException {
    if (finding.outcome() != GenericFindingAssessment.Outcome.PLANNED_PREREQUISITES_ABSENT) {
      return;
    }
    if (!MavenElisionReportProofValidator.isAutomaticallyVerifiable(finding)
        || finding.prerequisiteGroupStatus() != ClaimGroupStatus.DECLARED
        || prediction.groups().isEmpty()
        || prediction.groups().stream().anyMatch(group -> !group.disarmed())) {
      throw new IOException("Planned prerequisite absence is not supported by prediction groups");
    }
  }
}
