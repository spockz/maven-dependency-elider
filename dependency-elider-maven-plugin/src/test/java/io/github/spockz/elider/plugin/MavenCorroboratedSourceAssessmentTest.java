/* WHY: Proves SourceFile leads remain review-only while configured POM proof still works. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ConfidenceLevel;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises source review evidence through the Analysis assessment path. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
class MavenCorroboratedSourceAssessmentTest {
  /** Temporary root for all CVE, cache and JAR inputs. */
  @TempDir private Path tempDir;

  @Test
  void retainsExactSourceLeadsAndPreservesConfiguredPomPhysicalProof() throws IOException {
    final MavenCorroboratedSourceScenario.Prepared scenario =
        MavenCorroboratedSourceScenario.prepare(tempDir);
    final List<CorroboratedSourceClassCandidate> candidates =
        MavenCorroboratedSourceScenario.candidates(scenario.result());
    final MavenVulnerabilityAssessment.Result result = scenario.result();
    assertAll(
        "SourceFile leads stay review-only; configured owner remains proof authority",
        () -> assertThat(candidates).hasSize(3),
        () ->
            assertThat(candidates)
                .extracting(CorroboratedSourceClassCandidate::classEntry)
                .containsExactlyInAnyOrder(
                    "org.example.Helper", "org.example.Outer", "org.example.Outer"),
        () ->
            assertThat(candidates)
                .allSatisfy(
                    value ->
                        assertAll(
                            () ->
                                assertThat(value.confidenceLabel())
                                    .isEqualTo(ConfidenceLevel.MEDIUM),
                            () ->
                                assertThat(value.mappingStatus())
                                    .isEqualTo(
                                        CorroboratedSourceClassCandidate.MappingStatus
                                            .INCOMPLETE_REVIEW_ONLY),
                            () ->
                                assertThat(value.cnaAffectedEntryIdentity())
                                    .isEqualTo("containers.cna.affected[1]"),
                            () ->
                                assertThat(value.provenance().sourceRecordId())
                                    .isEqualTo(MavenCorroboratedSourceArchiveFixtures.CVE_ID),
                            () ->
                                assertThat(value.provenance().sourceRecordSha256())
                                    .isEqualTo(scenario.cveDigest()),
                            () ->
                                assertThat(value.artifactCoordinate())
                                    .isEqualTo(scenario.coordinate()),
                            () ->
                                assertThat(value.originalArchiveSha256())
                                    .isEqualTo(scenario.originalDigest().sha256()),
                            () ->
                                assertThat(value.programFile())
                                    .isEqualTo(MavenCorroboratedSourceArchiveFixtures.PROGRAM_FILE),
                            () ->
                                assertThat(value.sourceFileAttribute())
                                    .isEqualTo(
                                        MavenCorroboratedSourceArchiveFixtures
                                            .SOURCE_FILE_ATTRIBUTE),
                            () ->
                                assertThat(value.packagePathComparison())
                                    .contains("exact source location"))),
        () ->
            assertThat(candidates)
                .extracting(CorroboratedSourceClassCandidate::conventionalLayoutAssumed)
                .containsOnly(false),
        () ->
            assertThat(candidates)
                .extracting(CorroboratedSourceClassCandidate::physicalJarEntry)
                .containsExactlyInAnyOrder(
                    "org/example/Helper.class",
                    "META-INF/versions/17/org/example/Outer.class",
                    "org/example/Outer.class"),
        () ->
            assertThat(candidates)
                .extracting(CorroboratedSourceClassCandidate::multiReleaseTier)
                .containsExactlyInAnyOrder(0, 17, 0),
        () -> assertThat(result.attestations()).hasSize(1),
        () -> assertThat(result.provenVulnerableCodeAbsent()).hasSize(1),
        () -> assertThat(result.removedComponents()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty(),
        () -> assertNoPersistedCandidatesInMatchedRecords(result),
        () -> assertArchiveMutationRecomputesCandidates(scenario, candidates),
        () -> assertAmbiguousSourceSnapshotsAbstain(scenario));
  }

  @Test
  void cacheOnlySourceCandidatesCannotClassifyProvenSuccessfulTrim() throws IOException {
    final MavenCorroboratedSourceScenario.Prepared scenario =
        MavenCorroboratedSourceScenario.prepare(tempDir);
    final MavenVulnerabilityAssessment.Result result =
        MavenCorroboratedSourceScenario.assessWithoutOwnerAssertions(scenario);
    final List<CorroboratedSourceClassCandidate> candidates =
        MavenCorroboratedSourceScenario.candidates(result);

    assertAll(
        "cached review candidates stay outside every proof and classification collection",
        () -> assertThat(candidates).hasSize(3),
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty(),
        () -> assertThat(result.removedComponents()).isEmpty(),
        () -> assertNoPersistedCandidatesInMatchedRecords(result));
  }

  @Test
  void malformedSourceArchivesAbstainWithAssessmentDiagnostics() throws IOException {
    final MavenCorroboratedSourceScenario.Prepared scenario =
        MavenCorroboratedSourceScenario.prepare(tempDir);
    final Path malformedTierArchive = tempDir.resolve("malformed-tier.jar");
    MavenCorroboratedSourceArchiveFixtures.writeNonCanonicalVersionArchive(malformedTierArchive);

    assertAll(
        "unreadable physical archive metadata produces a diagnosed source-candidate abstention",
        () -> assertArchiveAbstains(scenario, malformedTierArchive));
  }

  private static void assertNoPersistedCandidatesInMatchedRecords(
      final MavenVulnerabilityAssessment.Result result) {
    assertAll(
        () -> assertThat(result.matchedAdvisoryRecords()).hasSize(1),
        () ->
            assertThat(result.matchedAdvisoryRecords())
                .allSatisfy(
                    matchedRecord ->
                        assertThat(matchedRecord.advisoryRecord().evidence())
                            .noneMatch(CorroboratedSourceClassCandidate.class::isInstance)));
  }

  private static void assertArchiveAbstains(
      final MavenCorroboratedSourceScenario.Prepared scenario, final Path archive)
      throws IOException {
    final MavenCorroboratedSourceScenario.AssessmentWithLog assessed =
        MavenCorroboratedSourceScenario.reassessWithArchive(scenario, archive);
    assertAll(
        () -> assertThat(MavenCorroboratedSourceScenario.candidates(assessed.result())).isEmpty(),
        () ->
            assertThat(assessed.log().warnings())
                .contains("Could not corroborate source-file claims in " + archive));
  }

  private static void assertArchiveMutationRecomputesCandidates(
      final MavenCorroboratedSourceScenario.Prepared scenario,
      final List<CorroboratedSourceClassCandidate> candidates)
      throws IOException {
    final String firstArchiveDigest = candidates.getFirst().originalArchiveSha256();
    MavenCorroboratedSourceArchiveFixtures.writeOriginalJar(scenario.originalJar(), true);
    final String changedArchiveDigest =
        io.github.spockz.elider.trimmer.ArtifactDigests.read(scenario.originalJar()).sha256();
    final MavenVulnerabilityAssessment.Result changedResult =
        MavenCorroboratedSourceScenario.reassess(scenario, true, false);
    final List<CorroboratedSourceClassCandidate> changedCandidates =
        MavenCorroboratedSourceScenario.candidates(changedResult);
    assertAll(
        "review provenance is recalculated from changed original JAR bytes",
        () -> assertThat(changedArchiveDigest).isNotEqualTo(firstArchiveDigest),
        () -> assertThat(changedCandidates).hasSize(3),
        () ->
            assertThat(changedCandidates)
                .allSatisfy(
                    value ->
                        assertThat(value.originalArchiveSha256()).isEqualTo(changedArchiveDigest)),
        () -> assertThat(changedResult.attestations()).isEmpty(),
        () -> assertThat(changedResult.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(changedResult.removedComponents()).isEmpty());
  }

  private static void assertAmbiguousSourceSnapshotsAbstain(
      final MavenCorroboratedSourceScenario.Prepared scenario) throws IOException {
    final MavenVulnerabilityAssessment.Result result =
        MavenCorroboratedSourceScenario.reassess(scenario, false, true);

    assertThat(result.matchedAdvisoryEvidence())
        .noneMatch(value -> value.evidence() instanceof CorroboratedSourceClassCandidate);
  }
}
