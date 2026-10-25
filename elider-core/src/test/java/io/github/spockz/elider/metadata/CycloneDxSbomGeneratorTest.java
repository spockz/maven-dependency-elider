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
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
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

    byte[] schemaBytes;
    try (InputStream schemaStream = getClass().getResourceAsStream("/schema/bom-1.6.schema.json")) {
      assertThat(schemaStream).isNotNull();
      schemaBytes = schemaStream.readAllBytes();
    }
    assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(schemaBytes)))
        .isEqualTo("18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d");
    JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);
    assertThat(factory.getSchema(JSON.readTree(schemaBytes)).validate(bom)).isEmpty();
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
}
