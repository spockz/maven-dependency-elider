// WHY: Keeps ADR-0008 serialization guarantees executable through Surefire's ADR test selection.

package io.github.spockz.elider.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.AtLeastOneConstructor",
  "PMD.UnitTestContainsTooManyAsserts",
  "checkstyle:AbbreviationAsWordInName"
})
@DisplayName("ADR-0008: precondition VEX serialization")
class ADR0008PreconditionVexSerializationTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final CycloneDxSbomGenerator CYCLONEDX = new CycloneDxSbomGenerator();
  private static final OpenVexGenerator OPENVEX = new OpenVexGenerator();
  private static final CycloneDxSbomGenerator.RootIdentity ROOT =
      new CycloneDxSbomGenerator.RootIdentity("com.example", "demo", "2.0", "Demo");
  private static final CycloneDxSbomGenerator.DocumentMetadata CYCLONEDX_METADATA =
      new CycloneDxSbomGenerator.DocumentMetadata(
          "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
          1,
          Instant.parse("2026-10-25T00:00:00Z"),
          "elider",
          "0.1.0");
  private static final OpenVexGenerator.DocumentMetadata OPENVEX_METADATA =
      new OpenVexGenerator.DocumentMetadata(
          "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
          "Elider Project",
          "Build System",
          Instant.parse("2026-10-25T00:00:00Z"),
          1);

  @TempDir Path temp;

  @Test
  void emitsSchemaValidPreconditionEvidenceWithoutTrimRecords() throws Exception {
    final PreconditionVexTestFixture fixture = PreconditionVexTestFixture.proven(temp);
    final ElisionDecision decision = retained(fixture.coordinate());
    final JsonNode bom =
        JSON.readTree(
            CYCLONEDX.generate(
                ROOT,
                List.of(fixture.inventory()),
                decision,
                CYCLONEDX_METADATA,
                List.of(),
                List.of(fixture.attestation(), fixture.attestation())));
    final JsonNode vulnerability = bom.path("vulnerabilities").get(0);
    assertThat(bom.path("vulnerabilities")).hasSize(1);
    assertThat(vulnerability.path("analysis").path("state").asText()).isEqualTo("not_affected");
    assertThat(vulnerability.path("analysis").path("justification").asText())
        .isEqualTo("requires_dependency");
    assertThat(vulnerability.path("analysis").path("detail").asText())
        .isEqualTo(fixture.attestation().impactDetail());
    final JsonNode component = bom.path("components").get(0);
    assertThat(component.path("hashes").get(0).path("content").asText())
        .isEqualTo(fixture.attestation().postElisionSha256());
    assertThat(component.path("pedigree").isMissingNode()).isTrue();
    assertCycloneDxSchemaValid(bom);

    final JsonNode openVex =
        JSON.readTree(
            OPENVEX.generate(
                ROOT,
                List.of(fixture.inventory()),
                List.of(fixture.attestation()),
                OPENVEX_METADATA));
    final JsonNode statement = openVex.path("statements").get(0);
    assertThat(statement.path("status").asText()).isEqualTo("not_affected");
    assertThat(statement.has("justification")).isFalse();
    assertThat(statement.path("impact_statement").asText())
        .isEqualTo(fixture.attestation().impactDetail());
    final JsonNode subcomponent = statement.path("products").get(0).path("subcomponents").get(0);
    assertThat(subcomponent.path("hashes").path("sha-256").asText())
        .isEqualTo(fixture.attestation().postElisionSha256());
    assertOpenVexSchemaValid(openVex);
  }

  @Test
  void rejectsMissingComponentsChangedPathsAndChangedAffectedBytes() throws Exception {
    final PreconditionVexTestFixture fixture = PreconditionVexTestFixture.proven(temp);
    final ElisionDecision decision = retained(fixture.coordinate());
    final Path alternatePath = temp.resolve("same-content-different-path.jar");
    Files.copy(fixture.inventory().filePath(), alternatePath);
    final ArtifactFileRef alternateInventory =
        ArtifactFileRef.fromPath(fixture.coordinate(), alternatePath);

    assertThatThrownBy(
            () ->
                CYCLONEDX.generate(
                    ROOT,
                    List.of(alternateInventory),
                    decision,
                    CYCLONEDX_METADATA,
                    List.of(),
                    List.of(fixture.attestation())))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("path does not match post-elision component");
    assertThatThrownBy(
            () ->
                OPENVEX.generate(
                    ROOT,
                    List.of(alternateInventory),
                    List.of(fixture.attestation()),
                    OPENVEX_METADATA))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("path does not match post-elision component");

    Files.writeString(fixture.inventory().filePath(), "mutated after proof");
    assertThatThrownBy(
            () ->
                CYCLONEDX.generate(
                    ROOT,
                    List.of(fixture.inventory()),
                    decision,
                    CYCLONEDX_METADATA,
                    List.of(),
                    List.of(fixture.attestation())))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("digest does not match post-elision component");
    assertThatThrownBy(
            () ->
                OPENVEX.generate(
                    ROOT,
                    List.of(fixture.inventory()),
                    List.of(fixture.attestation()),
                    OPENVEX_METADATA))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("digest does not match post-elision component");

    final Path otherPath = temp.resolve("unrelated.jar");
    Files.writeString(otherPath, "unrelated component");
    final ArtifactCoordinate other = ArtifactCoordinate.of("org.example", "other", "1.0");
    final ArtifactFileRef otherInventory = ArtifactFileRef.fromPath(other, otherPath);
    final ElisionDecision otherDecision = retained(other);
    assertThatThrownBy(
            () ->
                CYCLONEDX.generate(
                    ROOT,
                    List.of(otherInventory),
                    otherDecision,
                    CYCLONEDX_METADATA,
                    List.of(),
                    List.of(fixture.attestation())))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("does not match a retained component");
    assertThatThrownBy(
            () ->
                OPENVEX.generate(
                    ROOT,
                    List.of(otherInventory),
                    List.of(fixture.attestation()),
                    OPENVEX_METADATA))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("no matching post-elision component");
  }

  @Test
  void prefersOmittedCodeWhenBothProofTypesAddressTheSameCveAndComponent() throws Exception {
    final VexTestFixture fixture = VexTestFixture.proven(temp);
    final VexAttestation precondition = VexTestFixture.preconditionFor(fixture);
    final ElisionDecision decision = retained(fixture.coordinate());
    final List<ArtifactTrimRecord> trimRecords = List.of(fixture.trimRecord());

    final byte[] omittedCodeFirst =
        CYCLONEDX.generate(
            ROOT,
            List.of(fixture.inventory()),
            decision,
            CYCLONEDX_METADATA,
            trimRecords,
            List.of(fixture.attestation(), precondition));
    final byte[] preconditionFirst =
        CYCLONEDX.generate(
            ROOT,
            List.of(fixture.inventory()),
            decision,
            CYCLONEDX_METADATA,
            trimRecords,
            List.of(precondition, fixture.attestation()));
    assertThat(preconditionFirst).isEqualTo(omittedCodeFirst);
    final JsonNode bom = JSON.readTree(omittedCodeFirst);
    assertThat(bom.path("vulnerabilities").get(0).path("analysis").path("justification").asText())
        .isEqualTo("code_not_present");
    assertCycloneDxSchemaValid(bom);

    final byte[] openVexOmittedCodeFirst =
        OPENVEX.generate(
            ROOT,
            List.of(fixture.inventory()),
            List.of(fixture.attestation(), precondition),
            OPENVEX_METADATA);
    final byte[] openVexPreconditionFirst =
        OPENVEX.generate(
            ROOT,
            List.of(fixture.inventory()),
            List.of(precondition, fixture.attestation()),
            OPENVEX_METADATA);
    assertThat(openVexPreconditionFirst).isEqualTo(openVexOmittedCodeFirst);
    final JsonNode openVex = JSON.readTree(openVexOmittedCodeFirst);
    assertThat(openVex.path("statements").get(0).path("justification").asText())
        .isEqualTo("vulnerable_code_not_present");
    assertOpenVexSchemaValid(openVex);
  }

  @Test
  void rejectsConflictingPreconditionEvidenceRegardlessOfAttestationOrder() throws Exception {
    final VexTestFixture fixture = VexTestFixture.proven(temp);
    final VexAttestation firstPrecondition = VexTestFixture.preconditionFor(fixture);
    final VexAttestation secondPrecondition =
        VexTestFixture.preconditionFor(fixture, "org.example.AlternativeApi");
    final ElisionDecision decision = retained(fixture.coordinate());
    final List<List<VexAttestation>> orders =
        List.of(
            List.of(fixture.attestation(), firstPrecondition, secondPrecondition),
            List.of(firstPrecondition, secondPrecondition, fixture.attestation()));

    for (final List<VexAttestation> attestations : orders) {
      assertThatThrownBy(
              () ->
                  CYCLONEDX.generate(
                      ROOT,
                      List.of(fixture.inventory()),
                      decision,
                      CYCLONEDX_METADATA,
                      List.of(fixture.trimRecord()),
                      attestations))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Conflicting duplicate precondition VEX attestation");
      assertThatThrownBy(
              () ->
                  OPENVEX.generate(
                      ROOT, List.of(fixture.inventory()), attestations, OPENVEX_METADATA))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Conflicting duplicate precondition VEX attestation");
    }
  }

  private static ElisionDecision retained(final ArtifactCoordinate coordinate) {
    return new ElisionDecision(Set.of(coordinate), Set.of(), Map.of(), Map.of(), 0);
  }

  private void assertCycloneDxSchemaValid(final JsonNode bom) throws IOException {
    assertThat(
            schema(
                    "/schema/bom-1.6.schema.json",
                    SpecVersion.VersionFlag.V7,
                    "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d")
                .validate(bom))
        .isEmpty();
  }

  private void assertOpenVexSchemaValid(final JsonNode document) throws IOException {
    assertThat(
            schema(
                    "/schema/openvex-0.2.0.schema.json",
                    SpecVersion.VersionFlag.V202012,
                    "9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238")
                .validate(document))
        .isEmpty();
  }

  private com.networknt.schema.JsonSchema schema(
      final String resource, final SpecVersion.VersionFlag version, final String expectedSha256)
      throws IOException {
    try (InputStream input = getClass().getResourceAsStream(resource)) {
      assertThat(input).isNotNull();
      final byte[] schemaBytes = input.readAllBytes();
      assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(schemaBytes)))
          .isEqualTo(expectedSha256);
      return JsonSchemaFactory.getInstance(version).getSchema(JSON.readTree(schemaBytes));
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
