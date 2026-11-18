// WHY: Verifies standalone VEX output against the pinned official OpenVEX 0.2.0 schema.

package io.github.spockz.elider.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.LocalVariableCouldBeFinal"
})
class OpenVexGeneratorTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final OpenVexGenerator GENERATOR = new OpenVexGenerator();
  private static final CycloneDxSbomGenerator.RootIdentity ROOT =
      new CycloneDxSbomGenerator.RootIdentity("com.example", "demo", "2.0", "Demo");
  private static final OpenVexGenerator.DocumentMetadata METADATA =
      new OpenVexGenerator.DocumentMetadata(
          "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
          "Elider Project",
          "Build System",
          Instant.parse("2026-10-25T00:00:00Z"),
          1);

  @TempDir Path temp;

  @Test
  void emitsSchemaValidOpenVexWithExactProductComponentRefsAndHashes() throws Exception {
    VexTestFixture fixture = VexTestFixture.proven(temp);

    JsonNode document =
        JSON.readTree(
            GENERATOR.generate(
                ROOT,
                List.of(fixture.inventory()),
                List.of(fixture.attestation(), fixture.attestation()),
                METADATA));

    assertThat(document.path("@context").asText()).isEqualTo("https://openvex.dev/ns/v0.2.0");
    assertThat(document.path("@id").asText()).isEqualTo(METADATA.documentId());
    assertThat(document.path("author").asText()).isEqualTo(METADATA.author());
    assertThat(document.path("role").asText()).isEqualTo(METADATA.role());
    assertThat(document.path("statements")).hasSize(1);
    JsonNode statement = document.path("statements").get(0);
    assertThat(statement.path("vulnerability").path("name").asText()).isEqualTo("CVE-2025-12345");
    assertThat(statement.path("status").asText()).isEqualTo("not_affected");
    assertThat(statement.path("justification").asText()).isEqualTo("vulnerable_code_not_present");
    JsonNode product = statement.path("products").get(0);
    assertThat(product.path("@id").asText()).isEqualTo(CycloneDxSbomGenerator.rootBomRef(ROOT));
    JsonNode subcomponent = product.path("subcomponents").get(0);
    assertThat(subcomponent.path("@id").asText())
        .isEqualTo(CycloneDxSbomGenerator.componentPurl(fixture.coordinate()));
    assertThat(subcomponent.path("hashes").path("sha-256").asText())
        .isEqualTo(fixture.attestation().trimmedSha256());
    assertThat(PinnedJsonSchemaCache.openVex020().validate(document)).isEmpty();
  }

  @Test
  void failsClosedForUnmatchedComponentsAndEmptyEvidence() throws Exception {
    VexTestFixture fixture = VexTestFixture.proven(temp);
    ArtifactCoordinate other = ArtifactCoordinate.of("org.example", "other", "1.0");
    ArtifactFileRef otherInventory =
        ArtifactFileRef.fromPath(other, fixture.inventory().filePath());

    assertThatThrownBy(
            () ->
                GENERATOR.generate(
                    ROOT, List.of(otherInventory), List.of(fixture.attestation()), METADATA))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("no matching post-elision component");
    assertThatThrownBy(
            () -> GENERATOR.generate(ROOT, List.of(fixture.inventory()), List.of(), METADATA))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at least one verified statement");
  }

  @Test
  void writesAtomicallyAndCleansTemporaryFile() throws Exception {
    VexTestFixture fixture = VexTestFixture.proven(temp);
    Path output = temp.resolve("standalone.openvex.json");

    GENERATOR.write(
        output, ROOT, List.of(fixture.inventory()), List.of(fixture.attestation()), METADATA);

    assertThat(JSON.readTree(output.toFile()).path("statements")).hasSize(1);
    try (Stream<Path> files = Files.list(temp)) {
      assertThat(files.map(Path::getFileName).map(Path::toString))
          .noneMatch(name -> name.endsWith(".tmp"));
    }
  }
}
