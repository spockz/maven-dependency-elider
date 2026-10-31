/* WHY: Verifies strict schema-v1 OSV ownership and review-only evidence persistence. */

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
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveVersionClaim;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.ExplicitClassMappingEvidence;
import io.github.spockz.elider.model.ExplicitPrerequisiteEvidence;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.TooManyMethods"
})
class AdvisoryEvidenceCodecTest {
  private final AdvisoryEvidenceWriter writer = new AdvisoryEvidenceWriter();
  private final AdvisoryEvidenceReader reader = new AdvisoryEvidenceReader();
  private final ObjectMapper mapper = new ObjectMapper();

  @Test
  void roundTripsTypedVariantsAndTheirIndependentProvenance() throws IOException {
    final OsvAdvisoryRecord record = recordWithVariants();
    final List<OsvAdvisoryRecord> decoded = read(writer.encode(List.of(record)));

    assertAll(
        "typed evidence is owned by one OSV record",
        () ->
            assertThat(decoded)
                .singleElement()
                .satisfies(
                    value ->
                        assertThat(value.evidence())
                            .containsExactlyInAnyOrderElementsOf(record.evidence())),
        () -> assertThat(decoded.getFirst().osvId()).isEqualTo("GHSA-owner"),
        () -> assertThat(decoded.getFirst().aliases()).containsExactly("CVE-2025-12345"),
        () ->
            assertThat(decoded.getFirst().cnaAffectedEntries().getFirst().entryIdentity())
                .isEqualTo("containers.cna.affected[0]"),
        () ->
            assertThat(decoded.getFirst().evidence())
                .filteredOn(StructuredSourceClassEvidence.class::isInstance)
                .singleElement()
                .satisfies(
                    value ->
                        assertThat(
                                ((StructuredSourceClassEvidence) value).cnaAffectedEntryIdentity())
                            .isEqualTo("containers.cna.affected[0]")),
        () ->
            assertThat(decoded.getFirst().evidence())
                .extracting(value -> value.provenance().origin())
                .contains(
                    EvidenceOrigin.OSV,
                    EvidenceOrigin.CVE_LIST,
                    EvidenceOrigin.DESCRIPTION,
                    EvidenceOrigin.REFERENCE_URL),
        () ->
            assertThat(decoded.getFirst().cnaAffectedEntries())
                .singleElement()
                .satisfies(
                    entry ->
                        assertAll(
                            () ->
                                assertThat(entry.versions())
                                    .containsExactly(
                                        new CveVersionClaim(
                                            "1.0",
                                            "affected",
                                            "semver",
                                            "2.0",
                                            "2.1",
                                            List.of(Map.of("at", "1.5", "status", "unaffected")))),
                            () -> assertThat(entry.defaultStatus()).isEqualTo("affected"),
                            () ->
                                assertThat(entry.packageUrl())
                                    .isEqualTo("pkg:maven/org.example/library"),
                            () ->
                                assertThat(entry.collectionUrl())
                                    .isEqualTo("https://example.test/repository"),
                            () ->
                                assertThat(entry.programFiles())
                                    .containsExactly("src/main/java/org/example/Unknown.java"),
                            () -> assertThat(entry.programRoutines()).containsExactly("decode"))));
  }

  @Test
  void roundTripsLegacyCommitClassAsMediumReviewCandidate() throws IOException {
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate(
            "org.apache.httpcomponents", "httpclient", null, "jar", "", "compile");
    final AdvisoryScope scope =
        new AdvisoryScope(
            "CVE-2014-3577",
            coordinate,
            "(,4.3.5)",
            "Maven",
            "org.apache.httpcomponents:httpclient");
    final HeuristicCandidateEvidence commitCandidate =
        new HeuristicCandidateEvidence(
            scope,
            new AdvisoryProvenance(
                EvidenceOrigin.REFERENCE_URL,
                "GHSA-transcript-httpclient#reference:0",
                URI.create(
                    "https://github.com/apache/httpcomponents-client/commit/"
                        + "51cc67567765d67f878f0dcef61b5ded454d3122"),
                "a".repeat(64)),
            Set.of("org.apache.http.conn.ssl.AbstractVerifier"),
            Set.of("org.apache.httpcomponents:httpclient"));
    final OsvAdvisoryRecord record =
        new OsvAdvisoryRecord(
            "GHSA-transcript-httpclient",
            Set.of("CVE-2014-3577"),
            List.of(
                new OsvAffectedPackage(
                    "Maven",
                    "org.apache.httpcomponents:httpclient",
                    coordinate,
                    List.of(),
                    List.of())),
            List.of(),
            List.of(commitCandidate));
    final HeuristicCandidateEvidence decoded =
        (HeuristicCandidateEvidence)
            read(writer.encode(List.of(record))).getFirst().evidence().getFirst();

    assertAll(
        "the old commit-derived class remains review-only after schema-v1 persistence",
        () -> assertThat(decoded).isEqualTo(commitCandidate),
        () ->
            assertThat(decoded.confidenceLabel())
                .isEqualTo(io.github.spockz.elider.model.ConfidenceLevel.MEDIUM),
        () ->
            assertThat(decoded.candidateClasses())
                .containsExactly("org.apache.http.conn.ssl.AbstractVerifier"),
        () -> assertThat(decoded.provenance().origin()).isEqualTo(EvidenceOrigin.REFERENCE_URL),
        () ->
            assertThat(decoded.provenance().sourceUrl())
                .isEqualTo(commitCandidate.provenance().sourceUrl()));
  }

  @Test
  void retainsMavenPackageContextForRecordWithoutCveAlias() throws IOException {
    final OsvAdvisoryRecord noCve =
        new OsvAdvisoryRecord(
            "GHSA-no-cve",
            Set.of("GHSA-alias-only"),
            List.of(
                affectedPackage("Maven:https://repo.test", "org.example:library", List.of("2.1"))),
            List.of(),
            List.of());
    final OsvAdvisoryRecord decoded = read(writer.encode(List.of(noCve))).getFirst();

    assertAll(
        () -> assertThat(decoded.osvId()).isEqualTo("GHSA-no-cve"),
        () -> assertThat(decoded.aliases()).containsExactly("GHSA-alias-only"),
        () -> assertThat(decoded.evidence()).isEmpty(),
        () ->
            assertThat(decoded.affectedPackages())
                .singleElement()
                .satisfies(
                    value ->
                        assertAll(
                            () ->
                                assertThat(value.ecosystem()).isEqualTo("Maven:https://repo.test"),
                            () -> assertThat(value.packageName()).isEqualTo("org.example:library"),
                            () -> assertThat(value.versions()).containsExactly("2.1"))));
  }

  @Test
  void preservesDistinctRecordOwnersForSharedCveAndPackage() throws IOException {
    final OsvAdvisoryRecord first = recordWithVariants();
    final OsvAdvisoryRecord second =
        new OsvAdvisoryRecord(
            "GHSA-second-owner",
            Set.of("CVE-2025-12345"),
            first.affectedPackages(),
            List.of(),
            List.of(packageEvidence("GHSA-second-owner", scope())));
    final List<OsvAdvisoryRecord> decoded = read(writer.encode(List.of(second, first)));

    assertAll(
        () ->
            assertThat(decoded)
                .extracting(OsvAdvisoryRecord::osvId)
                .containsExactly("GHSA-owner", "GHSA-second-owner"),
        () ->
            assertThat(decoded.stream().filter(value -> value.aliases().contains("CVE-2025-12345")))
                .hasSize(2));
  }

  @Test
  void deterministicEncodingIgnoresRecordOrder() throws IOException {
    final OsvAdvisoryRecord first = recordWithVariants();
    final OsvAdvisoryRecord second =
        new OsvAdvisoryRecord("GHSA-other", Set.of(), List.of(), List.of(), List.of());

    assertThat(writer.encode(List.of(first, second)))
        .isEqualTo(writer.encode(List.of(second, first)));
  }

  @Test
  void rejectsFlatLegacyDocumentsUnsupportedSchemaAndMalformedOwnership() throws IOException {
    assertAll(
        () ->
            assertThatThrownBy(() -> reader.read(stream("{\"mappings\":[]}")))
                .isInstanceOf(IOException.class),
        () -> {
          final ObjectNode unsupported = mapper.createObjectNode();
          unsupported.put("schemaVersion", 2);
          unsupported.putArray("records");
          assertRejected(unsupported, "schemaVersion");
        },
        () -> {
          final ObjectNode duplicate =
              (ObjectNode)
                  mapper.readTree(writer.encode(List.of(recordWithVariants(), otherOwner())));
          duplicate.withArray("records").add(duplicate.withArray("records").get(0).deepCopy());
          assertRejected(duplicate, "Duplicate OSV record ID");
        },
        () ->
            assertThatThrownBy(
                    () ->
                        new OsvAdvisoryRecord(
                            "GHSA-owner",
                            Set.of("CVE-2025-12345"),
                            recordWithVariants().affectedPackages(),
                            List.of(),
                            List.of(packageEvidence("wrong-owner", scope()))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("provenance"));
  }

  @Test
  void ownerProofEvidenceCannotBePersistedOrLoadedFromCache() throws IOException {
    assertAll(
        "owner evidence remains outside persisted advisory cache",
        () ->
            assertThatThrownBy(
                    () ->
                        new OsvAdvisoryRecord(
                            "GHSA-owner",
                            Set.of("CVE-2025-12345"),
                            recordWithVariants().affectedPackages(),
                            List.of(),
                            List.of(ownerEvidence())))
                .isInstanceOf(IllegalArgumentException.class),
        () -> {
          final ObjectNode root = persistedOwnerDocument("explicit-class-mapping");
          assertRejected(root, "Owner proof evidence");
        },
        () -> {
          final ExplicitPrerequisiteEvidence prerequisite =
              ExplicitPrerequisiteEvidence.declare(
                  scope().cveId(),
                  scope().affectedCoordinate(),
                  scope().versionRangeSpec(),
                  "org.example:prerequisite",
                  "org.example.Prerequisite",
                  null,
                  io.github.spockz.elider.model.ConfidenceLevel.HIGH,
                  "effective-project-pom:vulnerabilityMappings[1]");
          assertThatThrownBy(
                  () ->
                      new OsvAdvisoryRecord(
                          "GHSA-owner",
                          Set.of("CVE-2025-12345"),
                          recordWithVariants().affectedPackages(),
                          List.of(),
                          List.of(prerequisite)))
              .isInstanceOf(IllegalArgumentException.class);
        },
        () ->
            assertRejected(
                persistedOwnerDocument("explicit-prerequisite"), "Owner proof evidence"));
  }

  @Test
  void rejectsUnknownFieldsDuplicateJsonKeysAndTrailingContent() throws IOException {
    assertAll(
        () -> {
          final ObjectNode unknown =
              (ObjectNode) mapper.readTree(writer.encode(List.of(recordWithVariants())));
          unknown.put("unexpected", true);
          assertRejected(unknown, "unknown field");
        },
        () ->
            assertThatThrownBy(
                    () ->
                        reader.read(
                            stream("{\"schemaVersion\":1,\"schemaVersion\":1,\"records\":[]}")))
                .isInstanceOf(IOException.class),
        () ->
            assertThatThrownBy(
                    () ->
                        reader.read(
                            stream(
                                new String(
                                        writer.encode(List.of(recordWithVariants())),
                                        StandardCharsets.UTF_8)
                                    + " {}")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("trailing"));
  }

  @Test
  void structuredEvidenceRemainsMediumAndRetainsUnresolvedEntries() {
    final StructuredSourceClassEvidence structured =
        (StructuredSourceClassEvidence)
            recordWithVariants().evidence().stream()
                .filter(StructuredSourceClassEvidence.class::isInstance)
                .findFirst()
                .orElseThrow();
    assertAll(
        () ->
            assertThat(structured.confidenceLabel())
                .isEqualTo(io.github.spockz.elider.model.ConfidenceLevel.MEDIUM),
        () -> assertThat(structured.scope().affectedCoordinate().version()).isNull(),
        () ->
            assertThat(structured.fileClassAttribution())
                .containsEntry("src/main/java/org/example/Unknown.java", Set.of()),
        () -> assertThat(structured.routineClassAttribution()).containsEntry("decode", Set.of()));
  }

  @Test
  void rejectsOverflowMissingUnknownInvalidProvenanceAndAttribution() throws IOException {
    assertAll(
        () -> {
          final ObjectNode overflow = documentWith(packageEvidence("GHSA-owner", scope()));
          overflow.put("schemaVersion", 4_294_967_297L);
          assertRejected(overflow, "schemaVersion");
        },
        () -> {
          final ObjectNode missingKind = documentWith(packageEvidence("GHSA-owner", scope()));
          ((ObjectNode) firstEvidence(missingKind)).remove("kind");
          assertRejected(missingKind, "kind");
        },
        () -> {
          final ObjectNode unknownKind = documentWith(packageEvidence("GHSA-owner", scope()));
          ((ObjectNode) firstEvidence(unknownKind)).put("kind", "future-kind");
          assertRejected(unknownKind, "Unknown advisory evidence discriminator");
        },
        () -> {
          final ObjectNode invalidOrigin = documentWith(packageEvidence("GHSA-owner", scope()));
          ((ObjectNode) firstEvidence(invalidOrigin))
              .withObject("provenance")
              .put("origin", EvidenceOrigin.CVE_LIST.name());
          assertRejected(invalidOrigin, "requires OSV provenance");
        },
        () -> {
          final ObjectNode invalidDigest = documentWith(packageEvidence("GHSA-owner", scope()));
          ((ObjectNode) firstEvidence(invalidDigest))
              .withObject("provenance")
              .put("sourceRecordSha256", "not-a-digest");
          assertRejected(invalidDigest, "SHA-256");
        },
        () ->
            assertThatThrownBy(
                    () ->
                        new AdvisoryProvenance(
                            EvidenceOrigin.CVE_LIST, "CVE-2025-12345", null, "invalid-digest"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SHA-256"),
        () -> {
          final ObjectNode incomplete = documentWith(structuredEvidenceVariant());
          ((ObjectNode) firstEvidence(incomplete)).putObject("fileClassAttribution");
          assertRejected(incomplete, "exact attribution");
        },
        () ->
            assertThatThrownBy(
                    () ->
                        new StructuredSourceClassEvidence(
                            scope(),
                            new AdvisoryProvenance(
                                EvidenceOrigin.CVE_LIST, "CVE-2025-12345", null, "a".repeat(64)),
                            "containers.cna.affected[0]",
                            "Example:library",
                            Set.of("src/main/java/org/example/Maybe.java"),
                            Set.of(),
                            Map.of(
                                "src/main/java/org/example/Maybe.java",
                                Set.of("org.example.Bad$Nested")),
                            Map.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("top-level class names"));
  }

  private OsvAdvisoryRecord recordWithVariants() {
    final AdvisoryScope scope = scope();
    final String digest = "a".repeat(64);
    final List<AdvisoryEvidence> evidence =
        List.of(
            packageEvidence("GHSA-owner", scope),
            new StructuredSourceClassEvidence(
                scope,
                new AdvisoryProvenance(EvidenceOrigin.CVE_LIST, "CVE-2025-12345", null, digest),
                "containers.cna.affected[0]",
                "Example:library",
                Set.of("src/main/java/org/example/Unknown.java"),
                Set.of("decode"),
                Map.of("src/main/java/org/example/Unknown.java", Set.of()),
                Map.of("decode", Set.of())),
            new HeuristicCandidateEvidence(
                scope,
                new AdvisoryProvenance(
                    EvidenceOrigin.DESCRIPTION, "GHSA-owner#summary", null, digest),
                Set.of("org.example.Possible"),
                Set.of("org.example:library")),
            new HeuristicCandidateEvidence(
                scope,
                new AdvisoryProvenance(
                    EvidenceOrigin.REFERENCE_URL,
                    "GHSA-owner#reference:0",
                    URI.create("https://example.test/fix"),
                    digest),
                Set.of(),
                Set.of("org.example:library")));
    return new OsvAdvisoryRecord(
        "GHSA-owner",
        Set.of("CVE-2025-12345"),
        List.of(affectedPackage("Maven", "org.example:library", List.of())),
        List.of(
            new CveAffectedEntryContext(
                "containers.cna.affected[0]",
                "Example",
                "library",
                "pkg:maven/org.example/library",
                "https://example.test/repository",
                "affected",
                List.of(
                    new CveVersionClaim(
                        "1.0",
                        "affected",
                        "semver",
                        "2.0",
                        "2.1",
                        List.of(Map.of("at", "1.5", "status", "unaffected")))),
                Set.of("src/main/java/org/example/Unknown.java"),
                Set.of("decode"))),
        evidence);
  }

  private OsvAdvisoryRecord otherOwner() {
    return new OsvAdvisoryRecord("GHSA-other", Set.of(), List.of(), List.of(), List.of());
  }

  private static OsvAffectedPackage affectedPackage(
      final String ecosystem, final String packageName, final List<String> versions) {
    return new OsvAffectedPackage(
        ecosystem,
        packageName,
        ArtifactCoordinate.of("org.example", "library", null),
        versions,
        List.of(
            new OsvAffectedRange(
                "ECOSYSTEM",
                "https://github.com/example/repo",
                List.of(Map.of("introduced", "0"), Map.of("fixed", "2.0")))));
  }

  private static PackageAdvisoryEvidence packageEvidence(
      final String owner, final AdvisoryScope scope) {
    return new PackageAdvisoryEvidence(
        scope, new AdvisoryProvenance(EvidenceOrigin.OSV, owner, null, "a".repeat(64)));
  }

  private static ExplicitClassMappingEvidence ownerEvidence() {
    return ExplicitClassMappingEvidence.declare(
        "CVE-2025-12345",
        ArtifactCoordinate.of("org.example", "library", "1.0"),
        "[1.0,2.0)",
        Set.of("org.example.Vulnerable"),
        null,
        io.github.spockz.elider.model.ConfidenceLevel.HIGH,
        "effective-project-pom:vulnerabilityMappings[0]");
  }

  private ObjectNode persistedOwnerDocument(final String discriminator) throws IOException {
    final ObjectNode document = documentWith(packageEvidence("GHSA-owner", scope()));
    ((ObjectNode) firstEvidence(document)).put("kind", discriminator);
    return document;
  }

  private ObjectNode documentWith(final AdvisoryEvidence evidence) throws IOException {
    final List<CveAffectedEntryContext> cnaEntries;
    if (evidence instanceof StructuredSourceClassEvidence structured) {
      final String productIdentity = structured.affectedProductIdentity();
      final int delimiter = productIdentity.indexOf(':');
      cnaEntries =
          List.of(
              new CveAffectedEntryContext(
                  structured.cnaAffectedEntryIdentity(),
                  productIdentity.substring(0, delimiter),
                  productIdentity.substring(delimiter + 1),
                  "pkg:maven/"
                      + structured.scope().affectedCoordinate().groupId()
                      + "/"
                      + structured.scope().affectedCoordinate().artifactId(),
                  null,
                  null,
                  List.of(),
                  structured.programFiles(),
                  structured.programRoutines()));
    } else {
      cnaEntries = List.of();
    }
    return (ObjectNode)
        mapper.readTree(
            writer.encode(
                List.of(
                    new OsvAdvisoryRecord(
                        "GHSA-owner",
                        Set.of("CVE-2025-12345"),
                        List.of(affectedPackage("Maven", "org.example:library", List.of())),
                        cnaEntries,
                        List.of(evidence)))));
  }

  private StructuredSourceClassEvidence structuredEvidenceVariant() {
    return recordWithVariants().evidence().stream()
        .filter(StructuredSourceClassEvidence.class::isInstance)
        .map(StructuredSourceClassEvidence.class::cast)
        .findFirst()
        .orElseThrow();
  }

  private static JsonNode firstEvidence(final ObjectNode document) {
    return ((ObjectNode) document.withArray("records").get(0)).withArray("evidence").get(0);
  }

  private static AdvisoryScope scope() {
    return new AdvisoryScope(
        "CVE-2025-12345",
        ArtifactCoordinate.of("org.example", "library", null),
        "[1.0,2.0)",
        "Maven",
        "org.example:library");
  }

  private List<OsvAdvisoryRecord> read(final byte[] payload) throws IOException {
    return reader.read(stream(payload));
  }

  private void assertRejected(final JsonNode document, final String message) throws IOException {
    assertThatThrownBy(() -> reader.read(stream(mapper.writeValueAsBytes(document))))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(message);
  }

  private static ByteArrayInputStream stream(final byte[] bytes) {
    return new ByteArrayInputStream(bytes);
  }

  private static ByteArrayInputStream stream(final String text) {
    return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
  }
}
