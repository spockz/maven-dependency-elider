// WHY: Keeps publication assertions grouped by persisted contract while sharing one real Mojo run.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import io.github.spockz.elider.model.StructuredProofProvenance;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Checks report, VEX, and manifest output from one run. */
final class MavenStructuredProofPublicationAssertions {
  /** Parses schema and output documents. */
  private static final ObjectMapper JSON = new ObjectMapper();

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
      final MavenStructuredProofPublicationScenario.PublishedResult result) {
    final MavenStructuredProofPublicationScenario.PublicationPaths paths = result.paths();
    final Path summaryPath = paths.summary();
    final Path classUsagePath = paths.classUsage();
    final MavenElisionReportSnapshot report = result.report();
    assertAll(
        "the historical report contains one live proof and no unresolved duplicate",
        () -> assertTrue(Files.isRegularFile(summaryPath), "published summary is missing"),
        () -> assertTrue(Files.isRegularFile(classUsagePath), "published class usage is missing"),
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

  /* default */ static void assertVexDocuments(
      final MavenStructuredProofPublicationScenario.PublishedResult result) throws IOException {
    final MavenStructuredProofPublicationScenario.PublicationPaths paths = result.paths();
    final Path sbomPath = paths.sbom();
    final Path baselineSbomPath = paths.baselineSbom();
    final Path vexPath = paths.vex();
    final JsonNode cycloneDx = result.cycloneDx();
    final JsonNode openVex = result.openVex();
    final JsonNode cdxSchema =
        JSON.readTree(
            Path.of("../elider-core/src/test/resources/schema/bom-1.6.schema.json").toFile());
    final JsonNode vexSchema =
        JSON.readTree(
            Path.of("../elider-core/src/test/resources/schema/openvex-0.2.0.schema.json").toFile());

    assertAll(
        "CycloneDX and OpenVEX carry only bounded proof provenance",
        () -> assertTrue(Files.isRegularFile(sbomPath), "published CycloneDX is missing"),
        () ->
            assertTrue(
                Files.isRegularFile(baselineSbomPath), "published baseline CycloneDX is missing"),
        () -> assertTrue(Files.isRegularFile(vexPath), "published OpenVEX is missing"),
        () -> assertThat(cycloneDx.path("vulnerabilities")).hasSize(1),
        () ->
            assertThat(
                    cycloneDx
                        .path("vulnerabilities")
                        .get(0)
                        .path("analysis")
                        .path("detail")
                        .asText())
                .contains(
                    "class absence for the recorded CNA claims only",
                    "cveSourceSha256",
                    "claimAttributions"),
        () -> assertThat(openVex.path("statements")).hasSize(1),
        () ->
            assertThat(openVex.path("statements").get(0).path("impact_statement").asText())
                .contains(
                    "does not independently validate vulnerability status", "claimAttributions"),
        () -> assertSchemaValid(cdxSchema, cycloneDx, SpecVersion.VersionFlag.V7),
        () -> assertSchemaValid(vexSchema, openVex, SpecVersion.VersionFlag.V202012));
  }

  /* default */ static void assertOutputManifest(
      final MavenStructuredProofPublicationScenario.PublishedResult result) throws IOException {
    final JsonNode manifest = result.manifestDocument();
    final MavenStructuredProofPublicationScenario.PublicationPaths outputPaths = result.paths();
    final Path manifestPath = outputPaths.manifest();
    final Path sbomPath = outputPaths.sbom();
    final Path baselineSbomPath = outputPaths.baselineSbom();
    final Path vexPath = outputPaths.vex();
    final List<String> paths = manifest.path("outputs").findValuesAsText("path");
    assertAll(
        "the transaction manifest records generated artifacts and their final bytes",
        () -> assertTrue(Files.isRegularFile(manifestPath), "generated-output manifest is missing"),
        () -> assertThat(paths).contains(path(sbomPath), path(baselineSbomPath)),
        () -> assertThat(paths).contains(path(vexPath)),
        () -> assertManifestDigest(manifest, sbomPath),
        () -> assertManifestDigest(manifest, baselineSbomPath),
        () -> assertManifestDigest(manifest, vexPath));
  }

  private static String path(final Path path) {
    return path.toAbsolutePath().normalize().toString();
  }

  private static void assertManifestDigest(final JsonNode manifest, final Path target)
      throws IOException {
    final List<JsonNode> entries =
        manifest.path("outputs").findParents("path").stream()
            .filter(entry -> path(target).equals(entry.path("path").asText()))
            .toList();
    assertThat(entries)
        .singleElement()
        .satisfies(
            entry ->
                assertThat(entry.path("sha256").asText())
                    .isEqualTo(ArtifactFileDigest.sha256(target)));
  }

  private static void assertSchemaValid(
      final JsonNode schema, final JsonNode document, final SpecVersion.VersionFlag schemaDraft) {
    assertThat(JsonSchemaFactory.getInstance(schemaDraft).getSchema(schema).validate(document))
        .isEmpty();
  }
}
