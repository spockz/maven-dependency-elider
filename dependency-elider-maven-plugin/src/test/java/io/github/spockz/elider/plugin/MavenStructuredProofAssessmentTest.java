// WHY: Verifies live structured source claims reach proof only after core physical checks.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises structured omitted-code proof through production Maven assessment. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class MavenStructuredProofAssessmentTest {
  /** Binary name used by the unique routine fixture. */
  private static final String OUTER_BINARY_NAME = "org.example.Outer";

  /** Binary name of a top-level sibling emitted by the shared source unit. */
  private static final String SIBLING_BINARY_NAME = "org.example.Sibling";

  /** Archive entry for a top-level sibling emitted by the shared source unit. */
  private static final String SIBLING_CLASS_ENTRY = "org/example/Sibling.class";

  /** Archive filename used by trimmed-output scenarios. */
  private static final String TRIMMED_JAR_FILENAME = "trimmed.jar";

  /** Routine name used by the unique source declaration. */
  private static final String PARSE_ROUTINE = "parse";

  /** Isolates generated archive fixtures for this test instance. */
  @TempDir private Path temporaryDirectory;

  @Test
  void liveStructuredAssessmentProducesProofOnlyAfterFullPhysicalOmissionCheck()
      throws IOException {
    final Path directory = temporaryDirectory.resolve("structured-proof");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve(TRIMMED_JAR_FILENAME));
    final MavenVulnerabilityAssessment.Result result =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);

    assertAll(
        "a live structured claim produces VEX only after current-source reproduction and pruning",
        () ->
            assertThat(result.attestations())
                .singleElement()
                .satisfies(
                    attestation ->
                        assertAll(
                            () ->
                                assertThat(attestation.cveId())
                                    .isEqualTo(MavenCorroboratedSourceArchiveFixtures.CVE_ID),
                            () ->
                                assertThat(attestation.evidenceSymbols())
                                    .contains(
                                        OUTER_BINARY_NAME,
                                        SIBLING_BINARY_NAME,
                                        "org.example.Outer$Nested",
                                        "org.example.Outer$1",
                                        "org.example.Outer$1Local",
                                        "org.example.SiblingContract",
                                        "org.example.SiblingKind",
                                        "org.example.SiblingAnnotation",
                                        "org.example.SiblingRecord"),
                            () ->
                                assertThat(attestation.structuredProofProvenance())
                                    .get()
                                    .satisfies(
                                        provenance ->
                                            assertThat(provenance.cnaAffectedEntryIdentity())
                                                .isEqualTo("containers.cna.affected[0]")))),
        () -> assertThat(result.provenVulnerableCodeAbsent()).hasSize(1),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty());
  }

  @Test
  void uniqueRoutineClaimProducesOnlyItsOwnerClassFamilyProof() throws IOException {
    final Path directory = temporaryDirectory.resolve("routine-structured-proof");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(), List.of(PARSE_ROUTINE));
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve(TRIMMED_JAR_FILENAME));

    final MavenVulnerabilityAssessment.Result result =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, false);

    assertAll(
        "a globally unique routine owner is physically checked without promoting its sibling",
        () ->
            assertThat(result.attestations())
                .singleElement()
                .satisfies(
                    attestation ->
                        assertAll(
                            () ->
                                assertThat(attestation.evidenceSymbols())
                                    .contains(
                                        OUTER_BINARY_NAME,
                                        "org.example.Outer$Nested",
                                        "org.example.Outer$1",
                                        "org.example.Outer$1Local")
                                    .doesNotContain(
                                        SIBLING_BINARY_NAME,
                                        "org.example.SiblingContract",
                                        "org.example.SiblingKind",
                                        "org.example.SiblingAnnotation",
                                        "org.example.SiblingRecord"),
                            () ->
                                assertThat(attestation.structuredProofProvenance())
                                    .get()
                                    .satisfies(
                                        provenance ->
                                            assertThat(provenance.claimAttributions())
                                                .anyMatch(
                                                    claim ->
                                                        claim.type()
                                                                == io.github.spockz.elider.model
                                                                    .StructuredProofProvenance
                                                                    .ClaimType.ROUTINE
                                                            && PARSE_ROUTINE.equals(claim.claim())
                                                            && OUTER_BINARY_NAME.equals(
                                                                claim.routineOwnerBinaryName()))))),
        () -> assertThat(result.provenVulnerableCodeAbsent()).hasSize(1),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty());
  }

  @Test
  void sameBasenamePackageSwapAbstainsBeforeItCanPromoteTheWrongClassFamily() throws IOException {
    final Path directory = temporaryDirectory.resolve("structured-proof-package-swap");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenAdversarialSourceArchiveFixtures.writePackagePathSwap(directory);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve(TRIMMED_JAR_FILENAME));

    final MavenVulnerabilityAssessment.Result result =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);

    assertAll(
        "byte-identical compilation cannot make a basename-only source claim identify a path",
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () ->
            assertThat(result.sourceCorrespondences())
                .anySatisfy(
                    correspondence ->
                        assertThat(correspondence)
                            .isInstanceOf(SourceBuildCorrespondence.Abstained.class)
                            .extracting(
                                value -> ((SourceBuildCorrespondence.Abstained) value).rationale())
                            .asString()
                            .contains("path disagrees with the declared Java package")));
  }

  @Test
  void structuredProofIsSuppressedWhenOneReproducedClaimClassSurvives() throws IOException {
    final Path directory = temporaryDirectory.resolve("structured-proof-survivor");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenAdversarialSourceArchiveFixtures.copyJarKeepingEntry(
            archives.originalJar(), directory.resolve(TRIMMED_JAR_FILENAME), SIBLING_CLASS_ENTRY);

    final MavenVulnerabilityAssessment.Result result =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);

    assertAll(
        "one surviving sibling class prevents structured omitted-code proof",
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty());
  }

  @Test
  void stalePersistedClassAttributionCannotSubstituteForLiveSourceOutputs() throws IOException {
    final Path directory = temporaryDirectory.resolve("structured-proof-stale-class-list");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.copyJarWithoutEntry(
            archives.originalJar(), directory.resolve(TRIMMED_JAR_FILENAME), SIBLING_CLASS_ENTRY);
    MavenStructuredProofCacheFixtures.setPersistedFileClassAttribution(
        prepared, MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY, SIBLING_BINARY_NAME);

    final MavenVulnerabilityAssessment.Result result =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);

    assertAll(
        "a stale persisted class list cannot hide the live claim's surviving Outer output",
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty());
  }

  @Test
  void competingCnaProductEntriesRemainReviewOnlyAndCannotMintProof() throws IOException {
    final Path directory = temporaryDirectory.resolve("structured-proof-ambiguous-product");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareAmbiguousProductClaim(directory, false);
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve(TRIMMED_JAR_FILENAME));

    final MavenVulnerabilityAssessment.Result result =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);

    assertAll(
        "conflicting affected and unaffected product entries do not grant structured proof",
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty());
  }

  @Test
  void structuredProofRequiresCurrentOsvAndCnaVersionAgreement() throws IOException {
    final Path directory = temporaryDirectory.resolve("structured-proof-version-disagreement");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    MavenStructuredProofCacheFixtures.setOsvAffectedVersions(prepared, List.of("2.0"));
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve(TRIMMED_JAR_FILENAME));

    final MavenVulnerabilityAssessment.Result result =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);

    assertAll(
        "current OSV versions do not mark the CNA-affected candidate affected",
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty());
  }
}
