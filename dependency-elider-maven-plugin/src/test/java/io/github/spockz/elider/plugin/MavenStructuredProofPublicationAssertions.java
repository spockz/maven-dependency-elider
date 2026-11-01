// WHY: Keeps publication assertions grouped by persisted contract while sharing one real Mojo run.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.spockz.elider.model.StructuredProofProvenance;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Checks report, VEX, and manifest output from one run. */
final class MavenStructuredProofPublicationAssertions {
  private MavenStructuredProofPublicationAssertions() {
    throw new AssertionError("No instances");
  }

  /* default */ static void assertSourceResolverWasUsed(
      final MavenStructuredProofPublicationScenario.PublishedResult result) {
    assertThat(result.sourceResolutions()).isPositive();
  }

  /* default */ static void assertSyntheticCve(
      final MavenStructuredProofPublicationScenario.PublishedResult result) {
    assertAll(
        "the source record is valid but unmistakably synthetic",
        () -> assertThat(result.cveSchemaErrors()).isEmpty(),
        () ->
            assertThat(result.syntheticCve().path("containers").path("cna").path("title").asText())
                .contains(MavenCorroboratedSourceArchiveFixtures.SYNTHETIC_RECORD_MARKER));
  }

  /* default */ static void assertSavedReport(
      final MavenStructuredProofPublicationScenario.PublishedResult result) throws IOException {
    final MavenStructuredProofPublicationScenario.PublicationPaths paths = result.paths();
    final Path summaryPath = paths.summary();
    final Path classUsagePath = paths.classUsage();
    assertAll(
        "the historical report contains one live proof and no unresolved duplicate",
        () -> assertTrue(Files.isRegularFile(summaryPath), "published summary is missing"),
        () -> assertTrue(Files.isRegularFile(classUsagePath), "published class usage is missing"),
        () -> assertSavedReportContents(summaryPath));
  }

  private static void assertSavedReportContents(final Path summaryPath) throws IOException {
    final MavenElisionReportSnapshot report = MavenElisionReportWriter.read(summaryPath);
    assertAll(
        () -> assertThat(report.verifiedStructuredProofs()).hasSize(1),
        () -> assertThat(report.provenAbsentCves()).hasSize(1),
        () -> assertThat(report.sourceReviewFindings()).isEmpty(),
        () ->
            assertThat(
                    report.verifiedStructuredProofs().getFirst().provenance().claimAttributions())
                .extracting(StructuredProofProvenance.ClaimAttribution::type)
                .containsExactlyInAnyOrder(
                    StructuredProofProvenance.ClaimType.FILE,
                    StructuredProofProvenance.ClaimType.ROUTINE));
  }
}
