// WHY: Locks the CycloneDX inventory to the applied dependency set and validates it offline.

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
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidDuplicateLiterals",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.LocalVariableCouldBeFinal",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts"
})
class CycloneDxSbomGeneratorTest {

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final CycloneDxSbomGenerator GENERATOR = new CycloneDxSbomGenerator();
  private static final CycloneDxSbomGenerator.RootIdentity ROOT =
      new CycloneDxSbomGenerator.RootIdentity("com.example", "demo", "2.0", "Demo");
  private static final CycloneDxSbomGenerator.DocumentMetadata METADATA =
      new CycloneDxSbomGenerator.DocumentMetadata(
          "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
          1,
          Instant.parse("2026-10-25T00:00:00Z"),
          "elider",
          "0.1.0");

  @TempDir Path temp;

  @Test
  void emitsStableSchemaValidInventoryAndDeduplicatesScopes() throws Exception {
    Path jar = temp.resolve("dep.jar");
    Files.writeString(jar, "artifact-bytes");
    ArtifactCoordinate compile =
        new ArtifactCoordinate("org.example", "codec+util", "1.2", "jar", "", "compile");
    ArtifactCoordinate test =
        new ArtifactCoordinate("org.example", "codec+util", "1.2", "jar", "", "test");
    ArtifactCoordinate elided = ArtifactCoordinate.of("org.example", "unused", "3.0");
    ArtifactFileRef first = ArtifactFileRef.fromPath(compile, jar);
    ArtifactFileRef second = ArtifactFileRef.fromPath(test, jar);
    ElisionDecision decision =
        new ElisionDecision(Set.of(compile, test), Set.of(elided), Map.of(), Map.of(), 0);
    byte[] firstJson = GENERATOR.generate(ROOT, List.of(first, second), decision, METADATA);
    byte[] secondJson = GENERATOR.generate(ROOT, List.of(second, first), decision, METADATA);
    assertThat(firstJson).isEqualTo(secondJson);

    JsonNode bom = JSON.readTree(firstJson);
    assertThat(bom.path("specVersion").asText()).isEqualTo("1.6");
    assertThat(bom.path("components")).hasSize(1);
    JsonNode component = bom.path("components").get(0);
    assertThat(component.path("purl").asText()).isEqualTo("pkg:maven/org.example/codec%2Butil@1.2");
    assertThat(component.path("properties").findValuesAsText("value"))
        .contains("compile,test", "jar");
    String expectedHash =
        HexFormat.of()
            .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar)));
    assertThat(component.path("hashes").get(0).path("content").asText()).isEqualTo(expectedHash);

    assertSchemaValid(readPinnedSchema(), bom);
  }

  @Test
  void generatesBaselineInventoryWithoutAnElisionDecision() throws Exception {
    Path retained = temp.resolve("baseline-retained.jar");
    Path elided = temp.resolve("baseline-elided.jar");
    Files.writeString(retained, "retained bytes");
    Files.writeString(elided, "pre-elision bytes");
    ArtifactCoordinate retainedCoordinate = ArtifactCoordinate.of("org.example", "retained", "1.0");
    ArtifactCoordinate laterElidedCoordinate =
        ArtifactCoordinate.of("org.example", "elided", "2.0");

    JsonNode bom =
        JSON.readTree(
            GENERATOR.generateBaseline(
                ROOT,
                List.of(
                    ArtifactFileRef.fromPath(retainedCoordinate, retained),
                    ArtifactFileRef.fromPath(laterElidedCoordinate, elided)),
                METADATA));

    assertThat(bom.path("components").findValuesAsText("bom-ref"))
        .containsExactly("pkg:maven/org.example/elided@2.0", "pkg:maven/org.example/retained@1.0");
    assertSchemaValid(readPinnedSchema(), bom);
  }

  @Test
  void emitsSchemaValidEmbeddedVexOnlyForProofBackedTrimmedComponents() throws Exception {
    VexTestFixture fixture = VexTestFixture.proven(temp);
    ElisionDecision decision =
        new ElisionDecision(Set.of(fixture.coordinate()), Set.of(), Map.of(), Map.of(), 0);

    byte[] bytes =
        GENERATOR.generate(
            ROOT,
            List.of(fixture.inventory()),
            decision,
            METADATA,
            List.of(fixture.trimRecord()),
            List.of(fixture.attestation(), fixture.attestation()));

    JsonNode bom = JSON.readTree(bytes);
    JsonNode component = bom.path("components").get(0);
    JsonNode vulnerability = bom.path("vulnerabilities").get(0);
    assertThat(bom.path("vulnerabilities")).hasSize(1);
    assertThat(vulnerability.path("id").asText()).isEqualTo("CVE-2025-12345");
    assertThat(vulnerability.path("analysis").path("state").asText()).isEqualTo("not_affected");
    assertThat(vulnerability.path("analysis").path("justification").asText())
        .isEqualTo("code_not_present");
    assertThat(vulnerability.path("affects").get(0).path("ref").asText())
        .isEqualTo(component.path("bom-ref").asText());
    assertThat(component.path("hashes").get(0).path("content").asText())
        .isEqualTo(fixture.attestation().trimmedSha256());
    assertThat(
            component
                .path("pedigree")
                .path("ancestors")
                .get(0)
                .path("hashes")
                .get(0)
                .path("content")
                .asText())
        .isEqualTo(fixture.attestation().originalSha256());
    assertSchemaValid(readPinnedSchema(), bom);
  }

  @Test
  void rejectsVexAttestationWhenTrimEvidenceDoesNotMatchThePostInventory() throws Exception {
    VexTestFixture fixture = VexTestFixture.proven(temp);
    Path changedTrimmed = temp.resolve("changed-trimmed.jar");
    Files.writeString(changedTrimmed, "not the proven trimmed artifact");
    ArtifactFileRef changedInventory =
        ArtifactFileRef.fromPath(fixture.coordinate(), changedTrimmed);
    ElisionDecision decision =
        new ElisionDecision(Set.of(fixture.coordinate()), Set.of(), Map.of(), Map.of(), 0);

    assertThatThrownBy(
            () ->
                GENERATOR.generate(
                    ROOT,
                    List.of(changedInventory),
                    decision,
                    METADATA,
                    List.of(fixture.trimRecord()),
                    List.of(fixture.attestation())))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("output path does not match");
  }

  @Test
  void writesSchemaValidTrimPedigreeWithOriginalAndTrimmedDigests() throws Exception {
    final Path original = temp.resolve("original.jar");
    final Path trimmed = temp.resolve("trimmed.jar");
    final Path output = temp.resolve("trimmed-bom.json");
    Files.writeString(original, "original artifact bytes");
    Files.writeString(trimmed, "trimmed artifact bytes");
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "library", "1.2");
    final ArtifactTrimRecord record = trimRecord(coordinate, original, trimmed, 12, 5);
    final ArtifactFileRef inventory = ArtifactFileRef.fromPath(coordinate, trimmed);
    final ElisionDecision decision =
        new ElisionDecision(Set.of(coordinate), Set.of(), Map.of(), Map.of(), 0);

    GENERATOR.write(output, ROOT, List.of(inventory), decision, METADATA, List.of(record));

    final JsonNode bom = JSON.readTree(output.toFile());
    final JsonNode component = bom.path("components").get(0);
    assertThat(component.path("hashes").get(0).path("content").asText())
        .isEqualTo(record.trimmedSha256());
    assertThat(component.path("pedigree").path("ancestors").get(0).path("purl").asText())
        .isEqualTo("pkg:maven/org.example/library@1.2");
    assertThat(component.path("bom-ref").asText())
        .isNotEqualTo(component.path("pedigree").path("ancestors").get(0).path("bom-ref").asText());
    assertThat(
            component
                .path("pedigree")
                .path("ancestors")
                .get(0)
                .path("hashes")
                .get(0)
                .path("content")
                .asText())
        .isEqualTo(record.originalSha256());
    assertThat(component.path("pedigree").path("patches").get(0).path("type").asText())
        .isEqualTo("unofficial");
    assertThat(
            component
                .path("pedigree")
                .path("patches")
                .get(0)
                .path("diff")
                .path("text")
                .path("content")
                .asText())
        .isEqualTo("Trimmed 7 unreferenced classes via ProGuard Core link closure");
    assertThat(component.path("properties").findValuesAsText("name"))
        .contains("elider:status", "elider:retainedClasses", "elider:totalClasses");
    assertThat(component.path("properties").findValuesAsText("value"))
        .contains("trimmed", "5", "12");

    assertSchemaValid(readPinnedSchema(), bom);
  }

  @Test
  void rejectsDuplicateOrOrphanTrimRecords() throws Exception {
    final Path original = temp.resolve("identity-original.jar");
    final Path trimmed = temp.resolve("identity-trimmed.jar");
    Files.writeString(original, "original");
    Files.writeString(trimmed, "trimmed");
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "present", "1");
    final ArtifactTrimRecord record = trimRecord(coordinate, original, trimmed, 2, 1);
    final ArtifactFileRef ref = ArtifactFileRef.fromPath(coordinate, trimmed);
    final ElisionDecision decision =
        new ElisionDecision(Set.of(coordinate), Set.of(), Map.of(), Map.of(), 0);

    assertThatThrownBy(
            () ->
                GENERATOR.generate(ROOT, List.of(ref), decision, METADATA, List.of(record, record)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate trim record");

    final ArtifactTrimRecord orphan =
        trimRecord(ArtifactCoordinate.of("org.example", "orphan", "1"), original, trimmed, 2, 1);
    assertThatThrownBy(
            () -> GENERATOR.generate(ROOT, List.of(ref), decision, METADATA, List.of(orphan)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("no retained inventory component");
  }

  @Test
  void rejectsTrimRecordPathAndDigestMismatches() throws Exception {
    final Path original = temp.resolve("mismatch-original.jar");
    final Path trimmed = temp.resolve("mismatch-trimmed.jar");
    final Path otherOutput = temp.resolve("mismatch-other.jar");
    Files.writeString(original, "original");
    Files.writeString(trimmed, "trimmed");
    Files.writeString(otherOutput, "other output");
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "mismatch", "1");
    final ArtifactTrimRecord record = trimRecord(coordinate, original, trimmed, 3, 2);
    final ArtifactFileRef ref = ArtifactFileRef.fromPath(coordinate, otherOutput);
    final ElisionDecision decision =
        new ElisionDecision(Set.of(coordinate), Set.of(), Map.of(), Map.of(), 0);

    assertThatThrownBy(
            () -> GENERATOR.generate(ROOT, List.of(ref), decision, METADATA, List.of(record)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("output path does not match");

    final ArtifactFileRef trimmedRef = ArtifactFileRef.fromPath(coordinate, trimmed);
    final ArtifactTrimRecord badDigest =
        new ArtifactTrimRecord(
            coordinate,
            original,
            record.originalSha256(),
            record.originalSha1(),
            trimmed,
            "0".repeat(64),
            record.trimmedSha1(),
            record.totalClasses(),
            record.retainedClasses(),
            record.prunedClassBytes());
    assertThatThrownBy(
            () ->
                GENERATOR.generate(
                    ROOT, List.of(trimmedRef), decision, METADATA, List.of(badDigest)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Trimmed artifact digest does not match");

    final ArtifactTrimRecord badOriginalDigest =
        new ArtifactTrimRecord(
            coordinate,
            original,
            "0".repeat(64),
            record.originalSha1(),
            trimmed,
            record.trimmedSha256(),
            record.trimmedSha1(),
            record.totalClasses(),
            record.retainedClasses(),
            record.prunedClassBytes());
    assertThatThrownBy(
            () ->
                GENERATOR.generate(
                    ROOT, List.of(trimmedRef), decision, METADATA, List.of(badOriginalDigest)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Original artifact digest does not match");
  }

  @Test
  void rejectsInventoryDecisionMismatchAndUnresolvedVersion() throws Exception {
    Path jar = temp.resolve("dep.jar");
    Files.writeString(jar, "bytes");
    ArtifactCoordinate retained = ArtifactCoordinate.of("org.example", "kept", "1");
    ElisionDecision decision =
        new ElisionDecision(Set.of(retained), Set.of(), Map.of(), Map.of(), 0);
    assertThatThrownBy(() -> GENERATOR.generate(ROOT, Set.of(), decision, METADATA))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("missing from applied inventory");

    ArtifactCoordinate unresolved = ArtifactCoordinate.of("org.example", "unknown", null);
    ArtifactFileRef ref = ArtifactFileRef.fromPath(unresolved, jar);
    ElisionDecision unresolvedDecision =
        new ElisionDecision(Set.of(unresolved), Set.of(), Map.of(), Map.of(), 0);
    assertThatThrownBy(() -> GENERATOR.generate(ROOT, Set.of(ref), unresolvedDecision, METADATA))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("unresolved version");
  }

  @Test
  void rejectsSerialNumbersOutsideLowercaseUuidPattern() {
    assertThatThrownBy(
            () ->
                new CycloneDxSbomGenerator.DocumentMetadata(
                    "not-a-uuid", 1, Instant.EPOCH, "elider", "0.1"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("lowercase urn:uuid");
    assertThatThrownBy(
            () ->
                new CycloneDxSbomGenerator.DocumentMetadata(
                    "urn:uuid:123E4567-E89B-12D3-A456-426614174000",
                    1,
                    Instant.EPOCH,
                    "elider",
                    "0.1"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("lowercase urn:uuid");
  }

  @Test
  void requiresEveryRetainedScopeVariantInAppliedInventory() throws Exception {
    Path jar = temp.resolve("scope-variant.jar");
    Files.writeString(jar, "bytes");
    ArtifactCoordinate compile =
        new ArtifactCoordinate("org.example", "shared", "1", "jar", "", "compile");
    ArtifactCoordinate test =
        new ArtifactCoordinate("org.example", "shared", "1", "jar", "", "test");
    ElisionDecision decision =
        new ElisionDecision(Set.of(compile, test), Set.of(), Map.of(), Map.of(), 0);
    ArtifactFileRef onlyCompile = ArtifactFileRef.fromPath(compile, jar);

    assertThatThrownBy(() -> GENERATOR.generate(ROOT, Set.of(onlyCompile), decision, METADATA))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("scope variant missing from applied inventory");
  }

  @Test
  void writesBomThroughPublicApi() throws Exception {
    Path jar = temp.resolve("written.jar");
    Path output = temp.resolve("written-bom.json");
    Files.writeString(jar, "bytes");
    ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "kept", "1");
    ElisionDecision decision =
        new ElisionDecision(Set.of(coordinate), Set.of(), Map.of(), Map.of(), 0);

    GENERATOR.write(
        output, ROOT, Set.of(ArtifactFileRef.fromPath(coordinate, jar)), decision, METADATA);

    JsonNode written = JSON.readTree(output.toFile());
    assertThat(written.path("bomFormat").asText()).isEqualTo("CycloneDX");
    assertThat(written.path("components")).hasSize(1);
    try (Stream<Path> files = Files.list(temp)) {
      assertThat(files.map(Path::getFileName).map(Path::toString))
          .noneMatch(name -> name.endsWith(".tmp"));
    }
  }

  @Test
  void replacementFailurePreservesExistingOutputAndCleansTemporaryFile() throws Exception {
    Path jar = temp.resolve("replacement.jar");
    Path output = temp.resolve("replace-bom.json");
    Files.writeString(jar, "bytes");
    Files.writeString(output, "previous");
    ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "kept", "1");
    ElisionDecision decision =
        new ElisionDecision(Set.of(coordinate), Set.of(), Map.of(), Map.of(), 0);
    AtomicReference<Path> temporaryPath = new AtomicReference<>();
    CycloneDxSbomGenerator failingGenerator =
        new CycloneDxSbomGenerator(
            (temporary, destination) -> {
              temporaryPath.set(temporary);
              throw new IOException("simulated atomic replacement failure");
            });

    assertThatThrownBy(
            () ->
                failingGenerator.write(
                    output,
                    ROOT,
                    List.of(ArtifactFileRef.fromPath(coordinate, jar)),
                    decision,
                    METADATA))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("simulated atomic replacement failure");
    assertThat(Files.readString(output)).isEqualTo("previous");
    assertThat(temporaryPath.get()).doesNotExist();
  }

  @Test
  void propagatesMissingArtifactHashInputWithoutReplacingExistingOutput() throws Exception {
    Path output = temp.resolve("bom.json");
    Files.writeString(output, "previous");
    ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "kept", "1");
    ArtifactFileRef missing = new ArtifactFileRef(coordinate, temp.resolve("missing.jar"), 0, 0);
    ElisionDecision decision =
        new ElisionDecision(Set.of(coordinate), Set.of(), Map.of(), Map.of(), 0);
    assertThatThrownBy(() -> GENERATOR.write(output, ROOT, Set.of(missing), decision, METADATA))
        .isInstanceOf(IOException.class);
    assertThat(Files.readString(output)).isEqualTo("previous");
  }

  private byte[] readPinnedSchema() throws IOException {
    try (InputStream schemaStream = getClass().getResourceAsStream("/schema/bom-1.6.schema.json")) {
      assertThat(schemaStream).isNotNull();
      final byte[] schemaBytes = schemaStream.readAllBytes();
      assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(schemaBytes)))
          .isEqualTo("18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d");
      return schemaBytes;
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private void assertSchemaValid(final byte[] schemaBytes, final JsonNode bom) throws IOException {
    final JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);
    assertThat(factory.getSchema(JSON.readTree(schemaBytes)).validate(bom)).isEmpty();
  }

  private static ArtifactTrimRecord trimRecord(
      final ArtifactCoordinate coordinate,
      final Path original,
      final Path trimmed,
      final int totalClasses,
      final int retainedClasses)
      throws IOException, NoSuchAlgorithmException {
    return new ArtifactTrimRecord(
        coordinate,
        original,
        digest(original, "SHA-256"),
        digest(original, "SHA-1"),
        trimmed,
        digest(trimmed, "SHA-256"),
        digest(trimmed, "SHA-1"),
        totalClasses,
        retainedClasses,
        0L);
  }

  private static String digest(final Path path, final String algorithm)
      throws IOException, NoSuchAlgorithmException {
    return HexFormat.of()
        .formatHex(MessageDigest.getInstance(algorithm).digest(Files.readAllBytes(path)));
  }
}
