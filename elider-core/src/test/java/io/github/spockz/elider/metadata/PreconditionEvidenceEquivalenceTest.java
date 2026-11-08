/* WHY: Checks that group operators and final member states identify VEX evidence. */

package io.github.spockz.elider.metadata;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.PreconditionClassInventory;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteMemberObservation;
import io.github.spockz.elider.model.PrerequisiteOperator;
import io.github.spockz.elider.model.VexAttestation;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises VEX identity against operator groups and final inventory observations. */
final class PreconditionEvidenceEquivalenceTest {
  /** Isolated directory for actual provider archives. */
  @TempDir private Path directory;

  @SuppressWarnings({"PMD.UnnecessaryConstructor", "PMD.UncommentedEmptyConstructor"})
  /* package */ PreconditionEvidenceEquivalenceTest() {}

  @Test
  void finalMemberPresenceIsExplicitInVexDetail() throws IOException {
    final PrerequisiteClaim firstMember = PreconditionEvidenceTestFixture.claimOne();
    final PrerequisiteClaim secondMember = PreconditionEvidenceTestFixture.claimTwo();
    final PrerequisiteGroup group =
        PreconditionEvidenceTestFixture.group(
            PrerequisiteOperator.ALL_OF, firstMember, secondMember);
    final PreconditionClassInventory onePresent =
        PreconditionClassInventory.complete(
            List.of(
                PreconditionEvidenceTestFixture.provider(
                    directory,
                    PreconditionEvidenceTestFixture.CANDIDATE,
                    "member-state-candidate.jar"),
                PreconditionEvidenceTestFixture.providerWithClass(
                    directory,
                    PreconditionEvidenceTestFixture.PROVIDER_ONE,
                    "first-member-present.jar",
                    PreconditionEvidenceTestFixture.CLASS_ONE),
                PreconditionEvidenceTestFixture.provider(
                    directory,
                    PreconditionEvidenceTestFixture.PROVIDER_TWO,
                    "second-member-absent.jar")));
    final PreconditionClassInventory otherPresent =
        PreconditionClassInventory.complete(
            List.of(
                PreconditionEvidenceTestFixture.provider(
                    directory, PreconditionEvidenceTestFixture.CANDIDATE, "other-candidate.jar"),
                PreconditionEvidenceTestFixture.provider(
                    directory,
                    PreconditionEvidenceTestFixture.PROVIDER_ONE,
                    "first-member-absent.jar"),
                PreconditionEvidenceTestFixture.providerWithClass(
                    directory,
                    PreconditionEvidenceTestFixture.PROVIDER_TWO,
                    "second-member-present.jar",
                    PreconditionEvidenceTestFixture.CLASS_TWO)));
    final VexAttestation first =
        PreconditionEvidenceTestFixture.prove(directory, "source-a", group, onePresent, onePresent)
            .attestation();
    final VexAttestation second =
        PreconditionEvidenceTestFixture.prove(
                directory, "source-b", group, otherPresent, otherPresent)
            .attestation();

    Assertions.assertAll(
        "VEX records each checked member state instead of claiming all members are absent",
        () ->
            assertThat(first.requiredPrerequisiteGroups())
                .isEqualTo(second.requiredPrerequisiteGroups()),
        () -> assertThat(first.inventorySha256()).isNotEqualTo(second.inventorySha256()),
        () ->
            assertThat(PreconditionEvidenceIdentity.from(first).memberObservations())
                .containsExactlyInAnyOrder(
                    new PrerequisiteMemberObservation(
                        firstMember, PrerequisiteMemberObservation.State.PRESENT),
                    new PrerequisiteMemberObservation(
                        secondMember, PrerequisiteMemberObservation.State.ABSENT)),
        () ->
            assertThat(PreconditionEvidenceIdentity.from(second).memberObservations())
                .containsExactlyInAnyOrder(
                    new PrerequisiteMemberObservation(
                        firstMember, PrerequisiteMemberObservation.State.ABSENT),
                    new PrerequisiteMemberObservation(
                        secondMember, PrerequisiteMemberObservation.State.PRESENT)),
        () ->
            assertThat(first.impactDetail())
                .contains(
                    PreconditionEvidenceTestFixture.CLASS_ONE + "=PRESENT",
                    PreconditionEvidenceTestFixture.CLASS_TWO + "=ABSENT"),
        () ->
            assertThat(second.impactDetail())
                .contains(
                    PreconditionEvidenceTestFixture.CLASS_ONE + "=ABSENT",
                    PreconditionEvidenceTestFixture.CLASS_TWO + "=PRESENT"),
        () -> assertThat(first.impactDetail()).isNotEqualTo(second.impactDetail()));
  }

  @Test
  void operatorChangesConflictEvenWhenEveryMemberIsAbsent() throws IOException {
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(
            List.of(
                PreconditionEvidenceTestFixture.provider(
                    directory,
                    PreconditionEvidenceTestFixture.CANDIDATE,
                    "operator-candidate.jar")));
    final Set<PrerequisiteClaim> claims =
        Set.of(
            PreconditionEvidenceTestFixture.claimOne(), PreconditionEvidenceTestFixture.claimTwo());
    final VexAttestation anyOf =
        PreconditionEvidenceTestFixture.prove(
                directory,
                "source-any",
                new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, claims),
                inventory,
                inventory)
            .attestation();
    final VexAttestation allOf =
        PreconditionEvidenceTestFixture.prove(
                directory,
                "source-all",
                new PrerequisiteGroup(PrerequisiteOperator.ALL_OF, claims),
                inventory,
                inventory)
            .attestation();

    Assertions.assertAll(
        () -> assertThat(anyOf.requiredPrerequisites()).isEqualTo(allOf.requiredPrerequisites()),
        () ->
            assertThat(anyOf.requiredPrerequisiteGroups())
                .isNotEqualTo(allOf.requiredPrerequisiteGroups()),
        () -> PreconditionEvidenceTestFixture.assertConflictingEvidence(anyOf, allOf));
  }

  @Test
  void sameFinalEvidenceComparisonRejectsChangedMemberStateWithEqualInventoryBinding() {
    final PrerequisiteClaim firstMember = PreconditionEvidenceTestFixture.claimOne();
    final PrerequisiteClaim secondMember = PreconditionEvidenceTestFixture.claimTwo();
    final Set<PrerequisiteGroup> groups =
        Set.of(
            PreconditionEvidenceTestFixture.group(
                PrerequisiteOperator.ALL_OF, firstMember, secondMember));
    final Set<PrerequisiteClaim> claims = Set.of(firstMember, secondMember);
    final String inventoryFingerprint = "b".repeat(64);
    final PreconditionEvidenceIdentity firstState =
        new PreconditionEvidenceIdentity(
            PreconditionEvidenceTestFixture.CANDIDATE,
            "requires_dependency",
            claims,
            groups,
            Set.of(
                new PrerequisiteMemberObservation(
                    firstMember, PrerequisiteMemberObservation.State.PRESENT),
                new PrerequisiteMemberObservation(
                    secondMember, PrerequisiteMemberObservation.State.ABSENT)),
            Path.of("target/library.jar"),
            "c".repeat(64),
            inventoryFingerprint);
    final PreconditionEvidenceIdentity reversedState =
        new PreconditionEvidenceIdentity(
            PreconditionEvidenceTestFixture.CANDIDATE,
            "requires_dependency",
            claims,
            groups,
            Set.of(
                new PrerequisiteMemberObservation(
                    firstMember, PrerequisiteMemberObservation.State.ABSENT),
                new PrerequisiteMemberObservation(
                    secondMember, PrerequisiteMemberObservation.State.PRESENT)),
            Path.of("target/library.jar"),
            "c".repeat(64),
            inventoryFingerprint);

    Assertions.assertAll(
        "member state is part of final-proof identity even when all other bindings match",
        () -> assertThat(firstState.inventorySha256()).isEqualTo(reversedState.inventorySha256()),
        () -> assertThat(firstState.groups()).isEqualTo(reversedState.groups()),
        () -> assertThat(firstState).isNotEqualTo(reversedState));
  }
}
