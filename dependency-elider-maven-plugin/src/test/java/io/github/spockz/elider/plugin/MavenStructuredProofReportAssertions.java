// WHY: Keeps report construction and payload integrity assertions independent from VEX output.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/** Assertions for strict typed and saved report proof invariants. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenStructuredProofReportAssertions {
  /** JSON mapper for reading saved report fixtures. */
  private static final ObjectMapper JSON = new ObjectMapper();

  private MavenStructuredProofReportAssertions() {}

  /** Checks typed snapshot duplicate and cross-collection invariants. */
  static void assertTypedSnapshotInvariants(
      final MavenElisionReportSnapshot snapshot,
      final MavenVulnerabilityAssessment.Result assessment) {
    final MavenElisionReportSnapshot.VerifiedStructuredProofFinding proof =
        snapshot.verifiedStructuredProofs().getFirst();
    final MavenElisionReportSnapshot.VerifiedStructuredProofFinding duplicate =
        MavenStructuredProofReportValidationFixtures.withOriginalDigest(
            MavenStructuredProofReportValidationFixtures.withProofRuntimeScope(proof),
            "0".repeat(64));
    final MavenElisionReportSnapshot.SourceReviewFinding fullyVerifiedReview =
        MavenStructuredProofReportValidationFixtures.sourceReviewFinding(
            assessment.matchedSourceClaims().getFirst());
    assertAll(
        "GAVCE identity ignores Maven scope",
        () ->
            assertThatThrownBy(() -> snapshotWithProofs(snapshot, List.of(proof, duplicate)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate verified structured proof identities"),
        () ->
            assertThatThrownBy(
                    () ->
                        snapshotWithSourceReviewFindings(
                            snapshot,
                            List.of(
                                MavenStructuredProofReportValidationFixtures.withReviewRuntimeScope(
                                    fullyVerifiedReview))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already fully represented as verified"),
        () ->
            assertThatCode(
                    () ->
                        snapshotWithSourceReviewFindings(
                            snapshot,
                            List.of(
                                MavenStructuredProofReportValidationFixtures.withUnresolvedRoutine(
                                    fullyVerifiedReview))))
                .doesNotThrowAnyException());
    final MavenElisionReportSnapshot.VerifiedStructuredProofFinding mismatchedLayout =
        MavenStructuredProofReportValidationFixtures.withLayoutAssumption(proof, false);
    assertThatThrownBy(() -> snapshotWithProofs(snapshot, List.of(mismatchedLayout)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("layout assumption must match the snapshot");
    assertThatThrownBy(
            () ->
                snapshotWithProofs(
                    snapshot,
                    List.of(
                        MavenStructuredProofReportValidationFixtures.withRawPackageName(
                            proof, "org.other:library"))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("raw OSV package identity conflicts with coordinate");
  }

  /** Checks strict saved-payload identity and separation invariants. */
  static void assertSavedPayloadInvariants(
      final Path report, final Path run, final MavenVulnerabilityAssessment.Result assessment)
      throws IOException {
    assertDuplicateAndLayoutPayloadsRejected(report, run);
    assertRawIdentityAndOverlapPayloadsRejected(
        report,
        run,
        MavenStructuredProofReportValidationFixtures.sourceReviewFinding(
            assessment.matchedSourceClaims().getFirst()));
  }

  private static void assertDuplicateAndLayoutPayloadsRejected(final Path report, final Path run)
      throws IOException {
    final JsonNode duplicatePayload = JSON.readTree(report.toFile());
    MavenStructuredProofReportPayloadMutator.appendDuplicateWithDifferentSourceDigestAndScope(
        duplicatePayload);
    final Path duplicateReport = run.resolve("duplicate-proof-report.json");
    JSON.writeValue(duplicateReport.toFile(), duplicatePayload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(duplicateReport))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("duplicate verified structured proof identity");

    final JsonNode mismatchedLayoutPayload = JSON.readTree(report.toFile());
    MavenStructuredProofReportPayloadMutator.changeProofLayoutAssumption(
        mismatchedLayoutPayload, false);
    final Path mismatchedLayoutReport = run.resolve("mismatched-layout-proof-report.json");
    JSON.writeValue(mismatchedLayoutReport.toFile(), mismatchedLayoutPayload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(mismatchedLayoutReport))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("layout assumption must match the snapshot");
  }

  private static void assertRawIdentityAndOverlapPayloadsRejected(
      final Path report,
      final Path run,
      final MavenElisionReportSnapshot.SourceReviewFinding fullyVerifiedReview)
      throws IOException {
    final JsonNode mismatchedPackagePayload = JSON.readTree(report.toFile());
    MavenStructuredProofReportPayloadMutator.changeProofRawScopeText(
        mismatchedPackagePayload, "osvPackageName", "org.other:library");
    final Path mismatchedPackageReport = run.resolve("mismatched-raw-package-report.json");
    JSON.writeValue(mismatchedPackageReport.toFile(), mismatchedPackagePayload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(mismatchedPackageReport))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("raw OSV package identity conflicts with coordinate");

    final JsonNode mismatchedEcosystemPayload = JSON.readTree(report.toFile());
    MavenStructuredProofReportPayloadMutator.changeProofRawScopeText(
        mismatchedEcosystemPayload, "osvEcosystem", "Mavenish");
    final Path mismatchedEcosystemReport = run.resolve("mismatched-ecosystem-report.json");
    JSON.writeValue(mismatchedEcosystemReport.toFile(), mismatchedEcosystemPayload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(mismatchedEcosystemReport))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("raw OSV package identity conflicts with coordinate");

    final JsonNode overlappingClaimsPayload = JSON.readTree(report.toFile());
    MavenStructuredProofReportPayloadMutator.appendSourceReviewFinding(
        overlappingClaimsPayload, fullyVerifiedReview);
    final Path overlappingClaimsReport = run.resolve("overlapping-claims-report.json");
    JSON.writeValue(overlappingClaimsReport.toFile(), overlappingClaimsPayload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(overlappingClaimsReport))
        .isInstanceOf(IOException.class)
        .hasRootCauseMessage(
            "Elision report source review claim is already fully represented as verified");

    final JsonNode mixedClaimsPayload = JSON.readTree(report.toFile());
    MavenStructuredProofReportPayloadMutator.appendSourceReviewFinding(
        mixedClaimsPayload,
        MavenStructuredProofReportValidationFixtures.withUnresolvedRoutine(fullyVerifiedReview));
    final Path mixedClaimsReport = run.resolve("mixed-verified-unresolved-claims-report.json");
    JSON.writeValue(mixedClaimsReport.toFile(), mixedClaimsPayload);
    assertThatCode(() -> MavenElisionReportWriter.read(mixedClaimsReport))
        .doesNotThrowAnyException();
  }

  private static MavenElisionReportSnapshot snapshotWithProofs(
      final MavenElisionReportSnapshot snapshot,
      final List<MavenElisionReportSnapshot.VerifiedStructuredProofFinding> proofs) {
    return new MavenElisionReportSnapshot(
        snapshot.schemaVersion(),
        snapshot.projectGroupId(),
        snapshot.projectArtifactId(),
        snapshot.projectVersion(),
        snapshot.projectBaseDirectory(),
        snapshot.generatedAt(),
        snapshot.wholeArtifactsDropped(),
        snapshot.originalJarBytesDropped(),
        snapshot.droppedProgramClassEntries(),
        snapshot.droppedProgramClassBytes(),
        snapshot.droppedArtifacts(),
        snapshot.rawDroppedCoordinates(),
        snapshot.programClassesPruned(),
        snapshot.uncompressedProgramClassBytesPruned(),
        snapshot.trimmedArtifacts(),
        snapshot.removedCveComponents(),
        snapshot.provenAbsentCves(),
        snapshot.inactivePreconditionCves(),
        snapshot.potentiallyConservativeCves(),
        snapshot.mediatedGraph(),
        snapshot.assumeConventionalJavaSourceLayout(),
        snapshot.sourceReviewFindings(),
        snapshot.advisoryReview(),
        proofs,
        snapshot.policy(),
        snapshot.exclusionReview());
  }

  private static MavenElisionReportSnapshot snapshotWithSourceReviewFindings(
      final MavenElisionReportSnapshot snapshot,
      final List<MavenElisionReportSnapshot.SourceReviewFinding> findings) {
    return new MavenElisionReportSnapshot(
        snapshot.schemaVersion(),
        snapshot.projectGroupId(),
        snapshot.projectArtifactId(),
        snapshot.projectVersion(),
        snapshot.projectBaseDirectory(),
        snapshot.generatedAt(),
        snapshot.wholeArtifactsDropped(),
        snapshot.originalJarBytesDropped(),
        snapshot.droppedProgramClassEntries(),
        snapshot.droppedProgramClassBytes(),
        snapshot.droppedArtifacts(),
        snapshot.rawDroppedCoordinates(),
        snapshot.programClassesPruned(),
        snapshot.uncompressedProgramClassBytesPruned(),
        snapshot.trimmedArtifacts(),
        snapshot.removedCveComponents(),
        snapshot.provenAbsentCves(),
        snapshot.inactivePreconditionCves(),
        snapshot.potentiallyConservativeCves(),
        snapshot.mediatedGraph(),
        snapshot.assumeConventionalJavaSourceLayout(),
        findings,
        snapshot.advisoryReview(),
        snapshot.verifiedStructuredProofs(),
        snapshot.policy(),
        snapshot.exclusionReview());
  }
}
