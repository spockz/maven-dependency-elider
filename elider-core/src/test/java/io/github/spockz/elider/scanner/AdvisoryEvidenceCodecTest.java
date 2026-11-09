/* WHY: Verifies strict schema-v1 OSV ownership and review-only evidence persistence. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.AdvisoryEvidence;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
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
    final boolean hasCnaEntries =
        writer.encodeTree(List.of(record)).path("records").get(0).has("cnaAffectedEntries");

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
            assertThat(decoded.getFirst().evidence())
                .extracting(value -> value.provenance().origin())
                .contains(
                    EvidenceOrigin.OSV, EvidenceOrigin.DESCRIPTION, EvidenceOrigin.REFERENCE_URL),
        () -> assertFalse(hasCnaEntries, "schema v1 omits the retired CNA field"));
  }

  @Test
  void schemaV1RejectsRetiredStructuredEvidenceAndCnaEntryShape() throws IOException {
    final ObjectNode legacy =
        (ObjectNode) mapper.readTree(writer.encode(List.of(recordWithVariants())));
    final ObjectNode legacyRecord = (ObjectNode) legacy.path("records").get(0);
    final ObjectNode oldCnaShape = legacy.deepCopy();
    ((ObjectNode) oldCnaShape.path("records").get(0)).putArray("cnaAffectedEntries");
    final ObjectNode oldStructuredTag = legacy.deepCopy();
    ((ObjectNode) firstEvidence(oldStructuredTag)).put("kind", "structured-source-class");
    final JsonNode encodedRecord =
        writer.encodeTree(List.of(recordWithVariants())).path("records").get(0);
    final boolean hasCnaEntries = encodedRecord.has("cnaAffectedEntries");
    final boolean hasLegacyCnaEntries = legacyRecord.has("cnaAffectedEntries");

    assertAll(
        "schema v1 accepts source-neutral advisory evidence only",
        () -> assertFalse(hasCnaEntries, "schema v1 omits the retired CNA field"),
        () -> assertFalse(hasLegacyCnaEntries, "schema v1 rejects the retired CNA field"),
        () -> assertRejected(oldCnaShape, "unknown field"),
        () -> assertRejected(oldStructuredTag, "Unknown advisory evidence discriminator"));
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
            "2026-10-31T00:00:00Z",
            Set.of("CVE-2014-3577"),
            List.of(
                new OsvAffectedPackage(
                    "Maven",
                    "org.apache.httpcomponents:httpclient",
                    coordinate,
                    List.of(),
                    List.of())),
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
            "2026-10-31T00:00:00Z",
            Set.of("GHSA-alias-only"),
            List.of(
                affectedPackage("Maven:https://repo.test", "org.example:library", List.of("2.1"))),
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
            "2026-10-31T00:00:00Z",
            Set.of("CVE-2025-12345"),
            first.affectedPackages(),
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
        new OsvAdvisoryRecord("GHSA-other", "2026-10-31T00:00:00Z", Set.of(), List.of(), List.of());

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
                            "2026-10-31T00:00:00Z",
                            Set.of("CVE-2025-12345"),
                            recordWithVariants().affectedPackages(),
                            List.of(packageEvidence("wrong-owner", scope()))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("provenance"));
  }

  @Test
  void rejectsSupersededEvidenceDiscriminators() throws IOException {
    assertAll(
        "schema v1 rejects evidence outside source-neutral advisory claims",
        () -> assertRejected(persistedOwnerDocument("structured-source-class"), "Unknown"),
        () ->
            assertRejected(
                persistedOwnerDocument("corroborated-source-class-candidate"), "Unknown"),
        () -> assertRejected(persistedOwnerDocument("explicit-class-mapping"), "Unknown"),
        () -> assertRejected(persistedOwnerDocument("explicit-prerequisite"), "Unknown"));
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
  void rejectsOverflowMissingUnknownAndInvalidProvenance() throws IOException {
    assertAll(
        () -> {
          final ObjectNode overflow = documentWith(packageEvidence("GHSA-owner", scope()));
          overflow.put("schemaVersion", 4_294_967_297L);
          assertRejected(overflow, "schemaVersion");
        },
        () -> {
          final ObjectNode invalidModified = documentWith(packageEvidence("GHSA-owner", scope()));
          ((ObjectNode) invalidModified.path("records").get(0)).put("modified", 123);
          assertRejected(invalidModified, "modified");
        },
        () -> {
          final ObjectNode nullModified = documentWith(packageEvidence("GHSA-owner", scope()));
          ((ObjectNode) nullModified.path("records").get(0)).putNull("modified");
          assertRejected(nullModified, "modified");
        },
        () -> {
          final ObjectNode invalidModified = documentWith(packageEvidence("GHSA-owner", scope()));
          ((ObjectNode) invalidModified.path("records").get(0)).put("modified", "not-a-timestamp");
          assertRejected(invalidModified, "modified");
        },
        () -> {
          final ObjectNode missingModified = documentWith(packageEvidence("GHSA-owner", scope()));
          ((ObjectNode) missingModified.path("records").get(0)).remove("modified");
          assertRejected(missingModified, "OSV record");
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
                .hasMessageContaining("SHA-256"));
  }

  private OsvAdvisoryRecord recordWithVariants() {
    final AdvisoryScope scope = scope();
    final String digest = "a".repeat(64);
    final List<AdvisoryEvidence> evidence =
        List.of(
            packageEvidence("GHSA-owner", scope),
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
        "2026-10-31T00:00:00Z",
        Set.of("CVE-2025-12345"),
        List.of(affectedPackage("Maven", "org.example:library", List.of())),
        evidence);
  }

  private OsvAdvisoryRecord otherOwner() {
    return new OsvAdvisoryRecord(
        "GHSA-other", "2026-10-31T00:00:00Z", Set.of(), List.of(), List.of());
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

  private ObjectNode persistedOwnerDocument(final String discriminator) throws IOException {
    final ObjectNode document = documentWith(packageEvidence("GHSA-owner", scope()));
    ((ObjectNode) firstEvidence(document)).put("kind", discriminator);
    return document;
  }

  private ObjectNode documentWith(final AdvisoryEvidence evidence) throws IOException {
    return (ObjectNode)
        mapper.readTree(
            writer.encode(
                List.of(
                    new OsvAdvisoryRecord(
                        "GHSA-owner",
                        "2026-10-31T00:00:00Z",
                        Set.of("CVE-2025-12345"),
                        List.of(affectedPackage("Maven", "org.example:library", List.of())),
                        List.of(evidence)))));
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
