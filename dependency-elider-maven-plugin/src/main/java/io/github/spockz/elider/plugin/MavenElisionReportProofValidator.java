/* WHY: Keeps saved proof rows from asserting outcomes their captured evidence cannot support. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.applicability.CodeAttributionResolver;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.CodeClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.VersionApplicability;
import java.io.IOException;
import java.util.List;

/** Checks the internal evidence needed to persist a verified proof outcome. */
final class MavenElisionReportProofValidator {
  private MavenElisionReportProofValidator() {}

  /* package */ static void validate(final GenericFindingAssessment finding) throws IOException {
    validateDetachedProofEvidence(finding);
    MavenElisionReportPredictionValidator.validatePrediction(finding, null);
    if (!isProof(finding.outcome())) {
      return;
    }
    if (!isAutomaticallyVerifiable(finding)) {
      throw new IOException(
          "Saved proof requires affected applicability and automatic verification");
    }
    validateRequiredEvidence(finding);
  }

  /* package */ static void validateForecast(
      final GenericFindingAssessment finding, final MavenElisionReportSnapshot snapshot)
      throws IOException {
    MavenElisionReportPredictionValidator.validatePrediction(finding, snapshot);
    if (finding.outcome() != GenericFindingAssessment.Outcome.PLANNED_CODE_ABSENT) {
      return;
    }
    if (snapshot.mode() != MavenElisionReportSnapshot.Mode.ANALYSIS
        || !isAutomaticallyVerifiable(finding)
        || finding.inventoryDisposition()
            != MavenVulnerabilityAssessment.InventoryDisposition.PLANNED_TRIM) {
      throw new IOException(
          "Planned code absence requires affected automatic analysis of a planned trim");
    }
    validateDeclaredCode(finding);
    final java.util.Set<String> required =
        finding.codeAttribution().stream()
            .filter(value -> value.claim().kind() == CodeClaim.Kind.DECLARED)
            .flatMap(value -> value.classFamily().stream())
            .collect(java.util.stream.Collectors.toSet());
    final boolean covered =
        snapshot.trimmedArtifacts().stream()
            .anyMatch(
                trim ->
                    MavenElisionReportSourceCoordinateValidator.parseCanonical(trim.coordinate())
                            .toId()
                            .equals(finding.candidate().toId())
                        && trim.plannedClasses() != null
                        && trim.plannedClasses().containsAll(required));
    if (!covered) {
      throw new IOException("Planned code absence is not supported by planned class removals");
    }
  }

  private static boolean isProof(final GenericFindingAssessment.Outcome outcome) {
    return outcome == GenericFindingAssessment.Outcome.DECLARED_CODE_ABSENT
        || outcome == GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT;
  }

  /* package */ static boolean isAutomaticallyVerifiable(final GenericFindingAssessment finding) {
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

  /* package */ static void validateDeclaredCode(final GenericFindingAssessment finding)
      throws IOException {
    final List<CodeAttributionResolver.DeclarationResult> declared =
        finding.codeAttribution().stream()
            .filter(value -> value.claim().kind() == CodeClaim.Kind.DECLARED)
            .toList();
    if (finding.codeGroupStatus() != ClaimGroupStatus.DECLARED
        || declared.isEmpty()
        || declared.stream()
            .anyMatch(
                value ->
                    value.status() != CodeAttributionResolver.Status.RESOLVED
                        || value.classFamily().isEmpty())) {
      throw new IOException("Saved code proof requires resolved declared code");
    }
  }

  private static void validatePrerequisites(final GenericFindingAssessment finding)
      throws IOException {
    if (finding.prerequisiteGroupStatus() != ClaimGroupStatus.DECLARED
        || finding.effectivePrerequisites().isEmpty()
        || finding.prerequisiteProofEvidence().isEmpty()) {
      throw new IOException("Saved prerequisite proof requires declared prerequisite pairs");
    }
  }

  private static void validateDetachedProofEvidence(final GenericFindingAssessment finding)
      throws IOException {
    final PrerequisiteProofEvidence evidence = finding.prerequisiteProofEvidence().orElse(null);
    if (finding.outcome() == GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT
        && evidence == null) {
      throw new IOException("Saved prerequisite proof requires prerequisiteProof evidence");
    }
    if (evidence == null) {
      return;
    }
    validateProofOutcome(finding);
    validateProofCandidate(finding, evidence);
    validateSelectedProofGroups(finding, evidence);
  }

  private static void validateProofOutcome(final GenericFindingAssessment finding)
      throws IOException {
    if (finding.outcome() != GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT) {
      throw new IOException("prerequisiteProof is not valid for this assessment outcome");
    }
  }

  private static void validateProofCandidate(
      final GenericFindingAssessment finding, final PrerequisiteProofEvidence evidence)
      throws IOException {
    if (!evidence.candidate().equals(finding.candidate())) {
      throw new IOException("prerequisiteProof.candidate does not match the finding candidate");
    }
  }

  private static void validateSelectedProofGroups(
      final GenericFindingAssessment finding, final PrerequisiteProofEvidence evidence)
      throws IOException {
    final java.util.Set<io.github.spockz.elider.model.PrerequisiteClaim> members =
        evidence.groups().stream()
            .flatMap(group -> group.group().members().stream())
            .collect(java.util.stream.Collectors.toSet());
    if (!members.equals(java.util.Set.copyOf(finding.effectivePrerequisites()))) {
      throw new IOException("prerequisiteProof.groups do not match selected prerequisite members");
    }
    final java.util.Set<PrerequisiteGroup> selectedGroups =
        java.util.Set.copyOf(
            MavenElisionReportFindingReconciliation.requireCanonicalFinding(
                    finding, "prerequisiteProof")
                .effectivePrerequisiteGroupsFor(finding.candidate().version()));
    final java.util.Set<PrerequisiteGroup> evidenceGroups =
        evidence.groups().stream()
            .map(PrerequisiteProofEvidence.GroupEvidence::group)
            .collect(java.util.stream.Collectors.toSet());
    for (int index = 0; index < evidence.groups().size(); index++) {
      final PrerequisiteGroup group = evidence.groups().get(index).group();
      validateSelectedGroup(group, index, selectedGroups);
    }
    if (!evidenceGroups.equals(selectedGroups)) {
      throw new IOException("prerequisiteProof.groups omit a selected source group");
    }
  }

  private static void validateSelectedGroup(
      final PrerequisiteGroup group,
      final int index,
      final java.util.Set<PrerequisiteGroup> selectedGroups)
      throws IOException {
    if (selectedGroups.contains(group)) {
      return;
    }
    final boolean sameMembers =
        selectedGroups.stream().anyMatch(value -> value.members().equals(group.members()));
    if (sameMembers) {
      throw new IOException(
          "prerequisiteProof.groups[" + index + "].operator differs from the selected source");
    }
    throw new IOException("prerequisiteProof.groups[" + index + "] is not a selected source group");
  }
}
