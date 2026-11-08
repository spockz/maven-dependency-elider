/* WHY: Proves baseline attribution does not alter final VEX proof identity. */

package io.github.spockz.elider.metadata;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.PreconditionClassInventory;
import io.github.spockz.elider.model.PrerequisiteAbsenceAttribution;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteOperator;
import io.github.spockz.elider.model.PrerequisiteProofResult;
import io.github.spockz.elider.model.VexAttestation;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks baseline-only causes and final-proof equivalence in one scenario. */
final class PreconditionBaselineAttributionTest {
  /** Isolated workspace for the provider archives. */
  @TempDir private Path directory;

  @SuppressWarnings({"PMD.UnnecessaryConstructor", "PMD.UncommentedEmptyConstructor"})
  /* package */ PreconditionBaselineAttributionTest() {}

  @Test
  // Independent observations share the actual archive and proof construction.
  @SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts", "PMD.UseConcurrentHashMap"})
  void baselineCausesDoNotChangeFinalVexEvidenceAndSourcesStillMerge() throws IOException {
    final PreconditionClassInventory.Provider candidateProvider =
        PreconditionEvidenceTestFixture.provider(
            directory, PreconditionEvidenceTestFixture.CANDIDATE, "candidate-final.jar");
    final PreconditionClassInventory.Provider retainedProvider =
        PreconditionEvidenceTestFixture.provider(
            directory, PreconditionEvidenceTestFixture.PROVIDER_TWO, "provider-final.jar");
    final PreconditionClassInventory actualFinal =
        PreconditionClassInventory.complete(List.of(candidateProvider, retainedProvider));
    final PrerequisiteGroup group =
        PreconditionEvidenceTestFixture.group(
            PrerequisiteOperator.ANY_OF, PreconditionEvidenceTestFixture.claimTwo());
    final PrerequisiteProofResult alreadyAbsent =
        PreconditionEvidenceTestFixture.prove(
            directory, "source-already-absent", group, actualFinal, actualFinal);
    final PrerequisiteProofResult trimmed =
        PreconditionEvidenceTestFixture.prove(
            directory,
            "source-trimmed",
            group,
            PreconditionClassInventory.complete(
                List.of(
                    candidateProvider,
                    PreconditionEvidenceTestFixture.providerWithClass(
                        directory,
                        PreconditionEvidenceTestFixture.PROVIDER_TWO,
                        "provider-original.jar",
                        PreconditionEvidenceTestFixture.CLASS_TWO))),
            actualFinal);
    final PrerequisiteProofResult elided =
        PreconditionEvidenceTestFixture.prove(
            directory,
            "source-elided",
            group,
            PreconditionClassInventory.complete(
                List.of(
                    candidateProvider,
                    PreconditionEvidenceTestFixture.providerWithClass(
                        directory,
                        PreconditionEvidenceTestFixture.PROVIDER_ONE,
                        "provider-dropped.jar",
                        PreconditionEvidenceTestFixture.CLASS_TWO))),
            actualFinal);
    final PrerequisiteProofResult mixed =
        PreconditionEvidenceTestFixture.prove(
            directory,
            "source-mixed",
            group,
            PreconditionClassInventory.complete(
                List.of(
                    candidateProvider,
                    PreconditionEvidenceTestFixture.providerWithClass(
                        directory,
                        PreconditionEvidenceTestFixture.PROVIDER_ONE,
                        "provider-mixed-dropped.jar",
                        PreconditionEvidenceTestFixture.CLASS_TWO),
                    PreconditionEvidenceTestFixture.providerWithClass(
                        directory,
                        PreconditionEvidenceTestFixture.PROVIDER_TWO,
                        "provider-mixed-original.jar",
                        PreconditionEvidenceTestFixture.CLASS_TWO))),
            actualFinal);
    final PrerequisiteProofResult unknown =
        PreconditionEvidenceTestFixture.prove(
            directory,
            "source-unknown",
            group,
            PreconditionClassInventory.incomplete(
                List.of(candidateProvider), "baseline unavailable"),
            actualFinal);
    final Map<String, VexAttestation> preconditions = new TreeMap<>();
    final PreconditionEvidenceIdentity finalEvidence =
        PreconditionEvidenceIdentity.from(alreadyAbsent.attestation());
    for (final PrerequisiteProofResult proof :
        List.of(alreadyAbsent, trimmed, elided, mixed, unknown)) {
      assertThat(PreconditionEvidenceIdentity.from(proof.attestation())).isEqualTo(finalEvidence);
      VexSerializerSupport.addAttestation(
          Map.of(), preconditions, proof.attestation().cveId(), proof.attestation());
    }

    Assertions.assertAll(
        "baseline attribution changes do not change final proof evidence",
        () ->
            assertThat(List.of(alreadyAbsent, trimmed, elided, mixed, unknown))
                .extracting(value -> value.groups().getFirst().attribution())
                .containsExactly(
                    PrerequisiteAbsenceAttribution.ALREADY_ABSENT,
                    PrerequisiteAbsenceAttribution.TRIMMED_CLASS,
                    PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY,
                    PrerequisiteAbsenceAttribution.MIXED,
                    PrerequisiteAbsenceAttribution.UNKNOWN),
        () -> assertThat(preconditions).hasSize(1),
        () ->
            assertThat(preconditions.values().iterator().next().sourceLabels())
                .contains(
                    "source-already-absent",
                    "source-trimmed",
                    "source-elided",
                    "source-mixed",
                    "source-unknown"),
        () ->
            assertThat(preconditions.values().iterator().next().impactDetail())
                .doesNotContain("baseline unavailable", "TRIMMED_CLASS", "ELIDED_DEPENDENCY"));
  }
}
