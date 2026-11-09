/* WHY: Guards the detached Analyze forecast report contract and its strict decoder. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.model.PrerequisiteAbsenceAttribution;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteMemberObservation;
import io.github.spockz.elider.model.PrerequisiteOperator;
import io.github.spockz.elider.model.VersionApplicability;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter",
  "PMD.AtLeastOneConstructor"
})
final class MavenElisionReportPrerequisitePredictionCodecTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  @Test
  void encodesAbsolutePathsAndRoundTripsTypedForecast() throws IOException {
    final PrerequisitePrediction prediction = prediction();
    final JsonNode encoded =
        MavenElisionReportPrerequisitePredictionCodec.encode(Optional.of(prediction));
    final JsonNode provider =
        encoded.path("groups").get(0).path("members").get(0).path("providers").get(0);

    assertAll(
        "forecast remains typed, detached report data",
        () -> assertThat(provider.path("baselinePath").isTextual()).isTrue(),
        () -> assertThat(provider.path("baselinePath").asText()).isEqualTo("/tmp/owner.jar"),
        () ->
            assertThat(MavenElisionReportPrerequisitePredictionCodec.decode(encoded))
                .contains(prediction),
        () ->
            assertThat(MavenElisionReportPrerequisitePredictionCodec.decode(JSON.nullNode()))
                .isEmpty());
  }

  @Test
  void rejectsUnknownFieldsDuplicateGroupsMembersProvidersAndRelativePaths() throws IOException {
    final JsonNode valid =
        MavenElisionReportPrerequisitePredictionCodec.encode(Optional.of(prediction()));
    final ObjectNode unknownField = ((ObjectNode) valid).deepCopy();
    unknownField.put("finalInventoryFingerprint", "a".repeat(64));
    final ObjectNode duplicateGroup = ((ObjectNode) valid).deepCopy();
    duplicateGroup.withArray("groups").add(duplicateGroup.path("groups").get(0).deepCopy());
    final ObjectNode duplicateMember = ((ObjectNode) valid).deepCopy();
    final ObjectNode selectedGroup =
        (ObjectNode) duplicateMember.path("groups").get(0).path("group");
    selectedGroup.withArray("members").add(selectedGroup.path("members").get(0).deepCopy());
    final ObjectNode duplicateProvider = ((ObjectNode) valid).deepCopy();
    final JsonNode member = duplicateProvider.path("groups").get(0).path("members").get(0);
    ((ObjectNode) member).withArray("providers").add(member.path("providers").get(0).deepCopy());
    final ObjectNode relativePath = ((ObjectNode) valid).deepCopy();
    ((ObjectNode)
            relativePath.path("groups").get(0).path("members").get(0).path("providers").get(0))
        .put("baselinePath", "owner.jar");

    assertAll(
        "strict prediction payload validation",
        () -> rejects(unknownField, "prerequisitePrediction fields"),
        () -> rejects(duplicateGroup, "groups contains duplicates"),
        () -> rejects(duplicateMember, "group.members contains duplicates"),
        () -> rejects(duplicateProvider, "provider paths must be distinct"),
        () -> rejects(relativePath, "baselinePath must be absolute"));
  }

  @Test
  void rejectsMalformedGroupForecastSemantics() throws IOException {
    final JsonNode valid =
        MavenElisionReportPrerequisitePredictionCodec.encode(Optional.of(prediction()));
    final ObjectNode missingMember = ((ObjectNode) valid).deepCopy();
    ((ObjectNode) missingMember.path("groups").get(0)).putArray("members");
    final ObjectNode incorrectDisarmed = ((ObjectNode) valid).deepCopy();
    ((ObjectNode) incorrectDisarmed.path("groups").get(0)).put("disarmed", false);

    assertAll(
        "forecast group and member semantics are checked by the model",
        () -> rejects(missingMember, "Prediction members do not match selected group"),
        () -> rejects(incorrectDisarmed, "Prediction group disarmed state is inconsistent"));
  }

  @Test
  void rejectsContradictoryForecastForRepeatedClaim() throws IOException {
    final PrerequisitePrediction absentPrediction = prediction();
    final PrerequisitePrediction.GroupForecast absent = absentPrediction.groups().getFirst();
    final ObjectNode contradictory =
        (ObjectNode)
            MavenElisionReportPrerequisitePredictionCodec.encode(Optional.of(absentPrediction));
    final ObjectNode present = ((ObjectNode) contradictory.withArray("groups").get(0)).deepCopy();
    ((ObjectNode) present.path("group")).put("operator", PrerequisiteOperator.ALL_OF.name());
    present.put("disarmed", false);
    final ObjectNode presentMember = (ObjectNode) present.withArray("members").get(0);
    presentMember.put("state", PrerequisitePrediction.MemberState.PRESENT.name());
    presentMember.put("reason", PrerequisitePrediction.MemberReason.PRESENT.name());
    ((ObjectNode) presentMember.withArray("providers").get(0))
        .put("plan", PrerequisitePrediction.ProviderPlan.RETAINED.name());
    contradictory.withArray("groups").add(present);

    assertAll(
        "a prerequisite claim has one baseline forecast across selected groups",
        () ->
            assertThatThrownBy(
                    () ->
                        new PrerequisitePrediction(
                            absentPrediction.candidate(),
                            absentPrediction.baselineInventoryFingerprint(),
                            absentPrediction.planFingerprint(),
                            List.of(
                                absent,
                                new PrerequisitePrediction.GroupForecast(
                                    new PrerequisiteGroup(
                                        PrerequisiteOperator.ALL_OF,
                                        Set.of(absent.members().getFirst().claim())),
                                    List.of(
                                        new PrerequisitePrediction.MemberForecast(
                                            absent.members().getFirst().claim(),
                                            PrerequisitePrediction.MemberState.PRESENT,
                                            PrerequisitePrediction.MemberReason.PRESENT,
                                            List.of(
                                                new PrerequisitePrediction.ProviderForecast(
                                                    ProviderKind.DEPENDENCY_ARCHIVE,
                                                    ArtifactCoordinate.of(
                                                        "org.example", "owner", "1.0"),
                                                    Path.of("/tmp/owner.jar"),
                                                    "a".repeat(64),
                                                    PrerequisitePrediction.ProviderPlan.RETAINED)),
                                            null)),
                                    false)),
                            null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("repeated member claim has conflicting forecast"),
        () -> rejects(contradictory, "repeated member claim has conflicting forecast"));
  }

  @Test
  void findingCannotCombinePhysicalAndPlannedPrerequisiteEvidence() {
    final PrerequisitePrediction prediction = prediction();
    final PrerequisitePrediction.GroupForecast selectedGroup = prediction.groups().getFirst();
    final PrerequisiteClaim claim = selectedGroup.members().getFirst().claim();
    final PrerequisiteProofEvidence physicalEvidence =
        new PrerequisiteProofEvidence(
            prediction.candidate(),
            "d".repeat(64),
            Path.of("/tmp/candidate.jar"),
            "e".repeat(64),
            List.of(
                new PrerequisiteProofEvidence.GroupEvidence(
                    selectedGroup.group(),
                    PrerequisiteAbsenceAttribution.ALREADY_ABSENT,
                    List.of(
                        new PrerequisiteProofEvidence.MemberEvidence(
                            claim,
                            PrerequisiteMemberObservation.State.ABSENT,
                            PrerequisiteAbsenceAttribution.ALREADY_ABSENT,
                            List.of())))),
            null);

    assertThatThrownBy(
            () ->
                new GenericFindingAssessment(
                    "CVE-2026-99002",
                    Set.of(),
                    prediction.candidate(),
                    VersionApplicability.AFFECTED,
                    Optional.of(AssessmentIntent.AUTO_VERIFY),
                    ClaimGroupStatus.OMITTED,
                    List.of(),
                    List.of(),
                    ClaimGroupStatus.DECLARED,
                    List.of(claim),
                    List.of(),
                    Set.of(),
                    Set.of(),
                    GenericFindingAssessment.Outcome.PLANNED_PREREQUISITES_ABSENT,
                    "forecast",
                    MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_UNCHANGED,
                    List.of(),
                    Optional.empty(),
                    Optional.of(physicalEvidence),
                    Optional.of(prediction)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Physical proof and Analyze prediction are distinct");
  }

  @Test
  void validatesAliasLinkedPomAndOsvPredictionAgainstCanonicalFinding() {
    final PrerequisitePrediction prediction = prediction();
    final ArtifactCoordinate candidate = prediction.candidate();
    final PrerequisiteGroup group = prediction.groups().getFirst().group();
    final VulnerabilityFindingContribution pom =
        aliasContribution("CVE-2026-99001", Set.of("POM-ALIAS"), candidate, group);
    final VulnerabilityFindingContribution osv =
        aliasContribution("GHSA-25qh-j22f-pwp8", Set.of("OSV-ALIAS"), candidate, group);
    final VulnerabilityFindingContribution bridge =
        aliasContribution("POM-ALIAS", Set.of("OSV-ALIAS"), candidate, group);
    final GenericFindingAssessment finding =
        new GenericFindingAssessment(
            "CVE-2026-99001",
            Set.of("CVE-2026-99001", "GHSA-25qh-j22f-pwp8", "POM-ALIAS", "OSV-ALIAS"),
            candidate,
            VersionApplicability.AFFECTED,
            Optional.of(AssessmentIntent.AUTO_VERIFY),
            ClaimGroupStatus.OMITTED,
            List.of(),
            List.of(),
            ClaimGroupStatus.DECLARED,
            group.members().stream().toList(),
            List.of(),
            Set.of(),
            Set.of(),
            GenericFindingAssessment.Outcome.PLANNED_PREREQUISITES_ABSENT,
            "forecast",
            MavenVulnerabilityAssessment.InventoryDisposition.PLANNED_TRIM,
            List.of(pom, bridge, osv),
            Optional.empty(),
            Optional.empty(),
            Optional.of(prediction));

    assertThatCode(() -> MavenElisionReportPredictionValidator.validatePrediction(finding, null))
        .doesNotThrowAnyException();
  }

  private static void rejects(final JsonNode node, final String message) {
    assertThatThrownBy(() -> MavenElisionReportPrerequisitePredictionCodec.decode(node))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(message);
  }

  private static PrerequisitePrediction prediction() {
    final ArtifactCoordinate owner = ArtifactCoordinate.of("org.example", "owner", "1.0");
    final PrerequisiteClaim claim =
        new PrerequisiteClaim("org.example:owner", "org.example.Absent");
    final PrerequisiteGroup group =
        new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, Set.of(claim));
    final PrerequisitePrediction.ProviderForecast provider =
        new PrerequisitePrediction.ProviderForecast(
            ProviderKind.DEPENDENCY_ARCHIVE,
            owner,
            Path.of("/tmp/owner.jar"),
            "a".repeat(64),
            PrerequisitePrediction.ProviderPlan.ELIDED);
    final PrerequisitePrediction.MemberForecast member =
        new PrerequisitePrediction.MemberForecast(
            claim,
            PrerequisitePrediction.MemberState.ABSENT,
            PrerequisitePrediction.MemberReason.WOULD_ELIDE_DEPENDENCY,
            List.of(provider),
            null);
    return new PrerequisitePrediction(
        ArtifactCoordinate.of("org.example", "candidate", "1.0"),
        "b".repeat(64),
        "c".repeat(64),
        List.of(new PrerequisitePrediction.GroupForecast(group, List.of(member), true)),
        null);
  }

  private static VulnerabilityFindingContribution aliasContribution(
      final String vulnerabilityId,
      final Set<String> aliases,
      final ArtifactCoordinate candidate,
      final PrerequisiteGroup group) {
    return new VulnerabilityFindingContribution(
        vulnerabilityId,
        aliases,
        candidate.groupId(),
        candidate.artifactId(),
        candidate.type(),
        candidate.classifier(),
        List.of(VersionCoverageClaim.affected("[1.0]")),
        FieldValue.omitted(),
        FieldValue.supplied(Set.of(group)),
        MergePriority.AUTOMATIC,
        AssessmentIntent.AUTO_VERIFY,
        "alias-prediction:" + vulnerabilityId,
        Set.of(),
        null);
  }
}
