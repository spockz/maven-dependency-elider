// WHY: Separates published security-document checks so each file is read within its own assertion
// group.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Validates separately persisted outputs from one production publication. */
final class MavenStructuredProofPublicationOutputAssertions {
  /** Parses output and pinned schema documents. */
  private static final ObjectMapper JSON = new ObjectMapper();

  private MavenStructuredProofPublicationOutputAssertions() {
    throw new AssertionError("No instances");
  }

  /* default */ static void assertVexDocuments(
      final MavenStructuredProofPublicationScenario.PublicationPaths paths) throws IOException {
    assertAll(
        "CycloneDX and OpenVEX carry only bounded proof provenance",
        () -> assertTrue(Files.isRegularFile(paths.sbom()), "published CycloneDX is missing"),
        () ->
            assertTrue(
                Files.isRegularFile(paths.baselineSbom()),
                "published baseline CycloneDX is missing"),
        () -> assertTrue(Files.isRegularFile(paths.vex()), "published OpenVEX is missing"),
        () -> assertCycloneDx(paths.sbom()),
        () -> assertOpenVex(paths.vex()));
  }

  /* default */ static void assertOutputManifest(
      final MavenStructuredProofPublicationScenario.PublicationPaths paths) throws IOException {
    assertAll(
        "the transaction manifest records generated artifacts and their final bytes",
        () ->
            assertTrue(
                Files.isRegularFile(paths.manifest()), "generated-output manifest is missing"),
        () -> assertManifestContents(paths));
  }

  private static void assertCycloneDx(final Path sbomPath) throws IOException {
    final JsonNode cycloneDx = JSON.readTree(sbomPath.toFile());
    final JsonNode cdxSchema =
        JSON.readTree(
            Path.of("../elider-core/src/test/resources/schema/bom-1.6.schema.json").toFile());
    assertAll(
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
        () -> assertSchemaValid(cdxSchema, cycloneDx, SpecVersion.VersionFlag.V7));
  }

  private static void assertOpenVex(final Path vexPath) throws IOException {
    final JsonNode openVex = JSON.readTree(vexPath.toFile());
    final JsonNode vexSchema =
        JSON.readTree(
            Path.of("../elider-core/src/test/resources/schema/openvex-0.2.0.schema.json").toFile());
    assertAll(
        () -> assertThat(openVex.path("statements")).hasSize(1),
        () ->
            assertThat(openVex.path("statements").get(0).path("impact_statement").asText())
                .contains(
                    "does not independently validate vulnerability status", "claimAttributions"),
        () -> assertSchemaValid(vexSchema, openVex, SpecVersion.VersionFlag.V202012));
  }

  private static void assertManifestContents(
      final MavenStructuredProofPublicationScenario.PublicationPaths paths) throws IOException {
    final JsonNode manifest = JSON.readTree(paths.manifest().toFile());
    final List<String> outputPaths = manifest.path("outputs").findValuesAsText("path");
    assertAll(
        () -> assertThat(outputPaths).contains(path(paths.sbom()), path(paths.baselineSbom())),
        () -> assertThat(outputPaths).contains(path(paths.vex())),
        () -> assertManifestDigest(manifest, paths.sbom()),
        () -> assertManifestDigest(manifest, paths.baselineSbom()),
        () -> assertManifestDigest(manifest, paths.vex()));
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
