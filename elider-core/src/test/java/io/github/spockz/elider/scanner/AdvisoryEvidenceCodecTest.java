/* WHY: Verifies typed persistence rejects malformed data and cannot mint proof inputs. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.AdvisoryEvidence;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.ExplicitClassMappingEvidence;
import io.github.spockz.elider.model.ExplicitPrerequisiteEvidence;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Exercises strict v1 codec round-trip and rejection behavior. */
@SuppressWarnings({"PMD.AvoidDuplicateLiterals", "PMD.TooManyMethods", "PMD.AtLeastOneConstructor"})
class AdvisoryEvidenceCodecTest {
  /** Writer used to create v1 test documents. */
  private final AdvisoryEvidenceWriter writer = new AdvisoryEvidenceWriter();

  /** Reader used to validate v1 test documents. */
  private final AdvisoryEvidenceReader reader = new AdvisoryEvidenceReader();

  /** Mapper used to mutate documents into invalid fixtures. */
  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void roundTripsAllCacheableVariantsWithScopeAndProvenance() throws IOException {
    final List<AdvisoryEvidence> evidence = cacheableEvidence();

    final List<AdvisoryEvidence> decoded = reader.read(stream(writer.encode(evidence)));

    assertAll(
        () -> assertThat(decoded).containsExactlyInAnyOrderElementsOf(evidence),
        () -> assertThat(decoded.stream().map(AdvisoryEvidence::scope).distinct()).hasSize(1),
        () -> assertThat(decoded.stream().map(AdvisoryEvidence::provenance).distinct()).hasSize(3));
  }

  @Test
  void writesEvidenceInDeterministicOrder() throws IOException {
    final List<AdvisoryEvidence> evidence = cacheableEvidence();
    final List<AdvisoryEvidence> reversed = new ArrayList<>(evidence);
    java.util.Collections.reverse(reversed);

    assertThat(writer.encode(evidence)).isEqualTo(writer.encode(reversed));
  }

  @Test
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  void freezesNestedCollections() {
    final Set<String> files = new java.util.LinkedHashSet<>(Set.of("src/main/java/a/A.java"));
    final Set<String> classes = new java.util.LinkedHashSet<>(Set.of("a.A"));
    final Map<String, Set<String>> fileMap = new java.util.LinkedHashMap<>();
    fileMap.put("src/main/java/a/A.java", classes);
    final StructuredSourceClassEvidence evidence =
        new StructuredSourceClassEvidence(
            scope(),
            cveProvenance(),
            "pkg:maven:org.example/library",
            files,
            Set.of(),
            fileMap,
            Map.of());
    files.clear();
    classes.clear();
    fileMap.clear();

    assertAll(
        () -> assertThat(evidence.programFiles()).containsExactly("src/main/java/a/A.java"),
        () -> assertThat(evidence.vulnerableClasses()).containsExactly("a.A"),
        () ->
            assertThatThrownBy(() -> evidence.programFiles().add("other.java"))
                .isInstanceOf(UnsupportedOperationException.class),
        () ->
            assertThatThrownBy(
                    () -> evidence.fileClassAttribution().get("src/main/java/a/A.java").clear())
                .isInstanceOf(UnsupportedOperationException.class));
  }

  @Test
  void structuredAttributionWithUnknownArtifactVersionRemainsReviewOnly() {
    final AdvisoryScope unspecifiedVersion =
        new AdvisoryScope(
            "CVE-2025-12345", ArtifactCoordinate.of("org.example", "library", null), "[1.0,2.0)");
    final StructuredSourceClassEvidence evidence =
        new StructuredSourceClassEvidence(
            unspecifiedVersion,
            cveProvenance(),
            "pkg:maven:org.example/library",
            Set.of("src/main/java/org/example/Vulnerable.java"),
            Set.of("parse"),
            Map.of("src/main/java/org/example/Vulnerable.java", Set.of("org.example.Vulnerable")),
            Map.of("parse", Set.of("org.example.Vulnerable")));

    assertAll(
        () ->
            assertAll(
                "structured candidate remains review-only",
                () -> assertThat(evidence.scope().affectedCoordinate().version()).isNull(),
                () ->
                    assertThat(evidence.confidenceLabel())
                        .isEqualTo(VulnerabilitySymbolMapping.ConfidenceLevel.MEDIUM),
                () -> assertThat(evidence).isNotInstanceOf(ExplicitClassMappingEvidence.class),
                () ->
                    assertThat(evidence.vulnerableClasses())
                        .containsExactly("org.example.Vulnerable")),
        () ->
            assertAll(
                "structured candidate round-trips without confidence promotion",
                () -> {
                  final List<AdvisoryEvidence> decoded =
                      reader.read(stream(writer.encode(List.of(evidence))));
                  assertAll(
                      () -> assertThat(decoded).containsExactly(evidence),
                      () ->
                          assertThat(decoded.get(0).confidenceLabel())
                              .isEqualTo(VulnerabilitySymbolMapping.ConfidenceLevel.MEDIUM));
                }));
  }

  @Test
  void roundTripsRoutineOnlyUnresolvedAndMixedStructuredAttribution() throws IOException {
    final StructuredSourceClassEvidence routineOnly =
        new StructuredSourceClassEvidence(
            scope(),
            cveProvenance(),
            "pkg:maven:org.example/library",
            Set.of(),
            Set.of("parse"),
            Map.of(),
            Map.of("parse", Set.of()));
    final StructuredSourceClassEvidence mixedAttribution =
        new StructuredSourceClassEvidence(
            scope(),
            cveProvenance(),
            "pkg:maven:org.example/library",
            Set.of(
                "src/main/java/org/example/Resolved.java",
                "src/main/java/org/example/Unresolved.java"),
            Set.of(),
            Map.of(
                "src/main/java/org/example/Resolved.java", Set.of("org.example.Resolved"),
                "src/main/java/org/example/Unresolved.java", Set.of()),
            Map.of());
    final List<AdvisoryEvidence> input = List.of(routineOnly, mixedAttribution);

    assertAll(
        () ->
            assertAll(
                "structured attribution retains unresolved entries",
                () -> assertThat(routineOnly.programRoutines()).containsExactly("parse"),
                () ->
                    assertThat(routineOnly.routineClassAttribution())
                        .containsEntry("parse", Set.of()),
                () -> assertThat(routineOnly.vulnerableClasses()).isEmpty(),
                () ->
                    assertThat(mixedAttribution.fileClassAttribution())
                        .containsEntry("src/main/java/org/example/Unresolved.java", Set.of()),
                () ->
                    assertThat(mixedAttribution.vulnerableClasses())
                        .containsExactly("org.example.Resolved")),
        () ->
            assertAll(
                "unresolved structured entries round-trip without promotion",
                () -> {
                  final List<AdvisoryEvidence> decoded = reader.read(stream(writer.encode(input)));
                  assertAll(
                      () -> assertThat(decoded).containsExactlyInAnyOrderElementsOf(input),
                      () ->
                          assertThat(decoded)
                              .allSatisfy(
                                  evidence ->
                                      assertThat(evidence.confidenceLabel())
                                          .isEqualTo(
                                              VulnerabilitySymbolMapping.ConfidenceLevel.MEDIUM)));
                }));
  }

  @Test
  void rejectsNullAndMalformedStructuredClassNames() {
    assertAll(
        () -> {
          final Set<String> nullClass = new java.util.LinkedHashSet<>();
          nullClass.add(null);
          assertThatThrownBy(
                  () ->
                      structuredEvidence(
                          Map.of("src/main/java/org/example/Vulnerable.java", nullClass)))
              .isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("non-blank strings");
        },
        () ->
            assertThatThrownBy(
                    () ->
                        structuredEvidence(
                            Map.of(
                                "src/main/java/org/example/Vulnerable.java",
                                Set.of("org.example.Bad$Inner"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("top-level class names"));
  }

  @Test
  void rejectsBlankAffectedCoordinateIdentity() {
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        new AdvisoryScope(
                            "CVE-2025-12345",
                            ArtifactCoordinate.of("", "library", null),
                            "[1.0,2.0)"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("groupId and artifactId"),
        () ->
            assertThatThrownBy(
                    () ->
                        new AdvisoryScope(
                            "CVE-2025-12345",
                            ArtifactCoordinate.of("org.example", "", null),
                            "[1.0,2.0)"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("groupId and artifactId"));
  }

  @Test
  void rejectsUnsupportedVersionsMissingAndUnknownDiscriminators() throws IOException {
    assertAll(
        () -> {
          final ObjectNode unsupported = documentWithOne(packageEvidence());
          unsupported.put("schemaVersion", 2);
          assertReadRejected(unsupported, "schemaVersion");
        },
        () -> {
          final ObjectNode overflow = documentWithOne(packageEvidence());
          overflow.put("schemaVersion", 4_294_967_297L);
          assertReadRejected(overflow, "schemaVersion");
        },
        () -> {
          final ObjectNode missingKind = documentWithOne(packageEvidence());
          ((ObjectNode) missingKind.withArray("evidence").get(0)).remove("kind");
          assertReadRejected(missingKind, "kind");
        },
        () -> {
          final ObjectNode unknownKind = documentWithOne(packageEvidence());
          ((ObjectNode) unknownKind.withArray("evidence").get(0)).put("kind", "future-kind");
          assertReadRejected(unknownKind, "Unknown advisory evidence discriminator");
        });
  }

  @Test
  void rejectsFlatHighRowsUnknownFieldsAndDuplicateKeys() throws IOException {
    assertAll(
        () ->
            assertThatThrownBy(
                    () -> reader.read(stream("{\"mappings\":[{\"confidenceLevel\":\"HIGH\"}]}")))
                .isInstanceOf(IOException.class),
        () -> {
          final ObjectNode unknownField = documentWithOne(packageEvidence());
          ((ObjectNode) unknownField.withArray("evidence").get(0)).put("unexpected", true);
          assertReadRejected(unknownField, "unknown field");
        },
        () ->
            assertThatThrownBy(
                    () ->
                        reader.read(
                            stream("{\"schemaVersion\":1,\"schemaVersion\":1,\"evidence\":[]}")))
                .isInstanceOf(IOException.class));
  }

  @Test
  void rejectsTrailingJsonAndIncompleteStructuredAttribution() throws IOException {
    assertAll(
        () -> {
          final String valid =
              new String(writer.encode(List.of(packageEvidence())), StandardCharsets.UTF_8);
          assertThatThrownBy(() -> reader.read(stream(valid + " {}")))
              .isInstanceOf(IOException.class)
              .hasMessageContaining("trailing");
        },
        () -> {
          final ObjectNode incomplete = documentWithOne(structuredEvidence());
          final ObjectNode structured = (ObjectNode) incomplete.withArray("evidence").get(0);
          structured.putObject("fileClassAttribution");
          assertReadRejected(incomplete, "exact attribution");
        });
  }

  @Test
  void ownerProofEvidenceCannotBePersistedOrLoadedFromCache() throws IOException {
    assertAll(
        () ->
            assertAll(
                "live explicit class evidence cannot be encoded",
                () -> {
                  final ExplicitClassMappingEvidence ownerEvidence =
                      ExplicitClassMappingEvidence.declare(
                          scope().cveId(),
                          scope().affectedCoordinate(),
                          scope().versionRangeSpec(),
                          Set.of("org.example.Vulnerable"),
                          null,
                          VulnerabilitySymbolMapping.ConfidenceLevel.HIGH,
                          "effective-project-pom:vulnerabilityMappings[0]");
                  assertAll(
                      () -> assertThat(ownerEvidence).isInstanceOf(AdvisoryEvidence.class),
                      () ->
                          assertThatThrownBy(() -> writer.encode(List.of(ownerEvidence)))
                              .isInstanceOf(IllegalArgumentException.class)
                              .hasMessageContaining("not part of the cacheable"));
                }),
        () ->
            assertAll(
                "persisted explicit class discriminator is refused",
                () -> {
                  final ObjectNode persistedOwner = mapper.createObjectNode();
                  persistedOwner.put("schemaVersion", 1);
                  final ObjectNode items = persistedOwner.putArray("evidence").addObject();
                  items.put("kind", "explicit-class-mapping");
                  items.putObject("scope");
                  items.putObject("provenance");
                  assertReadRejected(persistedOwner, "Owner proof evidence");
                }),
        () ->
            assertAll(
                "live explicit prerequisite evidence cannot be encoded",
                () -> {
                  final ExplicitPrerequisiteEvidence prerequisiteEvidence =
                      ExplicitPrerequisiteEvidence.declare(
                          scope().cveId(),
                          scope().affectedCoordinate(),
                          scope().versionRangeSpec(),
                          "org.example:prerequisite",
                          "org.example.Prerequisite",
                          null,
                          VulnerabilitySymbolMapping.ConfidenceLevel.HIGH,
                          "effective-project-pom:vulnerabilityMappings[1]");
                  assertAll(
                      () -> assertThat(prerequisiteEvidence).isInstanceOf(AdvisoryEvidence.class),
                      () ->
                          assertThatThrownBy(() -> writer.encode(List.of(prerequisiteEvidence)))
                              .isInstanceOf(IllegalArgumentException.class)
                              .hasMessageContaining("not part of the cacheable"));
                }),
        () ->
            assertAll(
                "persisted explicit prerequisite discriminator is refused",
                () -> {
                  final ObjectNode persistedPrerequisite = mapper.createObjectNode();
                  persistedPrerequisite.put("schemaVersion", 1);
                  persistedPrerequisite
                      .putArray("evidence")
                      .addObject()
                      .put("kind", "explicit-prerequisite");
                  assertReadRejected(persistedPrerequisite, "Owner proof evidence");
                }));
  }

  @Test
  void rejectsInvalidVariantOriginAndProvenanceDigest() throws IOException {
    assertAll(
        () -> {
          final ObjectNode wrongPackageOrigin = documentWithOne(packageEvidence());
          ((ObjectNode) wrongPackageOrigin.withArray("evidence").get(0))
              .withObject("provenance")
              .put("origin", EvidenceOrigin.REFERENCE_URL.name());
          assertReadRejected(wrongPackageOrigin, "requires OSV provenance");
        },
        () ->
            assertThatThrownBy(
                    () ->
                        new AdvisoryProvenance(
                            EvidenceOrigin.CVE_LIST, "CVE-2025-12345", null, "not-a-digest"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SHA-256"));
  }

  private List<AdvisoryEvidence> cacheableEvidence() {
    return List.of(
        structuredEvidence(),
        corroboratedEvidence(),
        new HeuristicCandidateEvidence(
            scope(),
            new AdvisoryProvenance(
                EvidenceOrigin.DESCRIPTION,
                "CVE-2025-12345-description",
                URI.create("https://osv.dev/vulnerability/GHSA-1234"),
                null),
            Set.of("org.example.Possible"),
            Set.of("org.example:dependency")),
        packageEvidence());
  }

  private StructuredSourceClassEvidence structuredEvidence() {
    return new StructuredSourceClassEvidence(
        scope(),
        cveProvenance(),
        "pkg:maven:org.example/library",
        Set.of("src/main/java/org/example/Vulnerable.java"),
        Set.of("parse"),
        Map.of("src/main/java/org/example/Vulnerable.java", Set.of("org.example.Vulnerable")),
        Map.of("parse", Set.of("org.example.Vulnerable")));
  }

  private StructuredSourceClassEvidence structuredEvidence(
      final Map<String, Set<String>> fileClassAttribution) {
    return new StructuredSourceClassEvidence(
        scope(),
        cveProvenance(),
        "pkg:maven:org.example/library",
        Set.of("src/main/java/org/example/Vulnerable.java"),
        Set.of(),
        fileClassAttribution,
        Map.of());
  }

  private CorroboratedSourceClassCandidate corroboratedEvidence() {
    return new CorroboratedSourceClassCandidate(
        scope(),
        cveProvenance(),
        "pkg:maven:org.example/library",
        "src/main/java/org/example/Vulnerable.java",
        "org.example.Vulnerable",
        "Vulnerable.java",
        "path package matches class package",
        false,
        CorroboratedSourceClassCandidate.MappingStatus.INCOMPLETE_REVIEW_ONLY);
  }

  private PackageAdvisoryEvidence packageEvidence() {
    return new PackageAdvisoryEvidence(
        scope(),
        new AdvisoryProvenance(
            EvidenceOrigin.OSV,
            "GHSA-1234",
            URI.create("https://osv.dev/vulnerability/GHSA-1234"),
            null));
  }

  private static AdvisoryScope scope() {
    return new AdvisoryScope(
        "CVE-2025-12345", ArtifactCoordinate.of("org.example", "library", null), "[1.0,2.0)");
  }

  private static AdvisoryProvenance cveProvenance() {
    return new AdvisoryProvenance(
        EvidenceOrigin.CVE_LIST,
        "CVE-2025-12345",
        URI.create("https://github.com/CVEProject/cvelistV5/CVE-2025-12345.json"),
        "a".repeat(64));
  }

  private ObjectNode documentWithOne(final AdvisoryEvidence evidence) throws IOException {
    return (ObjectNode) mapper.readTree(writer.encode(List.of(evidence)));
  }

  private void assertReadRejected(final JsonNode document, final String message)
      throws IOException {
    assertThatThrownBy(() -> reader.read(stream(mapper.writeValueAsBytes(document))))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(message);
  }

  private static ByteArrayInputStream stream(final byte[] value) {
    return new ByteArrayInputStream(value);
  }

  private static ByteArrayInputStream stream(final String value) {
    return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
  }
}
