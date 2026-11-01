// WHY: Confirms correspondence and live proof share claim-independent invocation work.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.correspondence.SourceReproductionEngine;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises production invocation reuse. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class MavenSourceReproductionReuseTest {
  /** Isolates all generated cache and archive files for the test instance. */
  @TempDir private Path temporaryDirectory;

  @Test
  void independentAdvisoriesReuseOneCandidateReproductionAndProduceTwoProofs() throws IOException {
    final Path directory = temporaryDirectory.resolve("same-artifact-advisories");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    MavenSourceReproductionReuseFixtures.installSecondCveOwner(prepared);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve("trimmed.jar"));
    final MavenSourceCorrespondenceAssessment sourceAssessment =
        MavenStructuredProofScenario.sourceAssessment(archives, true, ignored -> {});

    final MavenVulnerabilityAssessment.Result result =
        MavenSourceReproductionReuseScenarios.assessSingle(
            prepared, archives, trimmed, true, sourceAssessment);
    final SourceReproductionEngine.InvocationDiagnostics diagnostics =
        sourceAssessment.invocationDiagnostics().orElseThrow();

    assertAll(
        "two independent advisories are revalidated against one candidate reproduction",
        () -> assertThat(result.attestations()).hasSize(2),
        () ->
            assertThat(result.attestations())
                .extracting(VexAttestation::cveId)
                .containsExactlyInAnyOrder(
                    MavenCorroboratedSourceArchiveFixtures.CVE_ID,
                    MavenSourceReproductionReuseFixtures.SECOND_CVE_ID),
        () ->
            assertThat(result.attestations())
                .extracting(VexAttestation::coordinate)
                .containsExactly(prepared.coordinate(), prepared.coordinate()),
        () -> assertThat(diagnostics.originalArchiveParses()).isEqualTo(1),
        () -> assertThat(diagnostics.sourceArchiveParses()).isEqualTo(1),
        () -> assertThat(diagnostics.compilerInvocations()).isEqualTo(1),
        () -> assertThat(diagnostics.reproductionCacheHits()).isEqualTo(3),
        () -> assertThat(diagnostics.physicalInventoryReusesFromReproduction()).isEqualTo(2));
  }

  @Test
  void separateArtifactsReuseBuildsAcrossAnInterveningReviewOnlyCandidate() throws IOException {
    final Path directory = temporaryDirectory.resolve("multiple-advisories");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final ArtifactCoordinate reviewCoordinate =
        ArtifactCoordinate.of("org.example", "middle-review", "1.0");
    final ArtifactCoordinate secondCoordinate =
        ArtifactCoordinate.of("org.example", "other-demo", "1.0");
    MavenSourceReproductionReuseFixtures.installTwoArtifactOwners(
        prepared, secondCoordinate, reviewCoordinate);
    final Path secondOriginal = directory.resolve("second-original.jar");
    Files.copy(archives.originalJar(), secondOriginal);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve("trimmed.jar"));
    final List<ArtifactTrimRecord> trimRecords =
        List.of(
            MavenSourceReproductionReuseScenarios.trimRecord(
                prepared.coordinate(), archives.originalJar(), trimmed),
            MavenSourceReproductionReuseScenarios.trimRecord(
                secondCoordinate, secondOriginal, trimmed));
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots =
        List.of(
            new ElisionAnalysisModel.ArtifactSnapshot(
                null, prepared.coordinate(), archives.originalJar()),
            new ElisionAnalysisModel.ArtifactSnapshot(null, reviewCoordinate, secondOriginal),
            new ElisionAnalysisModel.ArtifactSnapshot(null, secondCoordinate, secondOriginal));
    final ElisionAnalysisModel.Analysis analysis =
        MavenCorroboratedSourceAnalysisFixtures.analysisWithSnapshots(snapshots, trimRecords);
    final MavenSourceCorrespondenceAssessment sourceAssessment =
        MavenSourceReproductionReuseScenarios.sourceAssessmentByArtifact(
            Map.of(
                sourceKey(prepared.coordinate()), archives.sourcesJar(),
                sourceKey(secondCoordinate), archives.sourcesJar()),
            true);
    final MavenVulnerabilityAssessment.Result result =
        MavenSourceReproductionReuseScenarios.assess(prepared, analysis, sourceAssessment);
    final SourceReproductionEngine.InvocationDiagnostics diagnostics =
        sourceAssessment.invocationDiagnostics().orElseThrow();

    assertAll(
        "proofs on both sides of a review-only candidate retain exact candidate cache entries",
        () -> assertThat(result.attestations()).hasSize(2),
        () ->
            assertThat(result.attestations())
                .extracting(VexAttestation::cveId)
                .containsExactlyInAnyOrder(
                    MavenCorroboratedSourceArchiveFixtures.CVE_ID,
                    MavenSourceReproductionReuseFixtures.SECOND_CVE_ID),
        () ->
            assertThat(result.attestations())
                .extracting(VexAttestation::coordinate)
                .containsExactlyInAnyOrder(prepared.coordinate(), secondCoordinate),
        () -> assertThat(diagnostics.originalArchiveParses()).isEqualTo(2),
        () -> assertThat(diagnostics.sourceArchiveParses()).isEqualTo(2),
        () -> assertThat(diagnostics.compilerInvocations()).isEqualTo(2),
        () -> assertThat(diagnostics.reproductionCacheHits()).isEqualTo(2),
        () -> assertThat(diagnostics.physicalInventoryReusesFromReproduction()).isEqualTo(2));
  }

  @Test
  void productionProofReusesCorrespondenceAndPhysicalInventoryWithinOneAssessment()
      throws IOException {
    final Path directory = temporaryDirectory.resolve("correspondence-and-proof");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(
            directory.resolve("trimmed.jar"));
    final MavenSourceCorrespondenceAssessment sourceAssessment =
        MavenStructuredProofScenario.sourceAssessment(archives, true, ignored -> {});

    final MavenVulnerabilityAssessment.Result result =
        MavenSourceReproductionReuseScenarios.assessSingle(
            prepared, archives, trimmed, true, sourceAssessment);
    final SourceReproductionEngine.InvocationDiagnostics diagnostics =
        sourceAssessment.invocationDiagnostics().orElseThrow();

    assertAll(
        "live proof consumes shared immutable reproduction and current physical inventory work",
        () -> assertThat(result.attestations()).hasSize(1),
        () -> assertThat(diagnostics.originalArchiveParses()).isEqualTo(1),
        () -> assertThat(diagnostics.sourceArchiveParses()).isEqualTo(1),
        () -> assertThat(diagnostics.compilerInvocations()).isEqualTo(1),
        () -> assertThat(diagnostics.reproductionCacheHits()).isEqualTo(1),
        () -> assertThat(diagnostics.physicalInventoryReusesFromReproduction()).isEqualTo(1),
        () -> assertThat(diagnostics.physicalInventoryParses()).isEqualTo(1));
  }

  private static String sourceKey(final ArtifactCoordinate coordinate) {
    return coordinate.groupId() + ":" + coordinate.artifactId() + ":" + coordinate.version();
  }
}
