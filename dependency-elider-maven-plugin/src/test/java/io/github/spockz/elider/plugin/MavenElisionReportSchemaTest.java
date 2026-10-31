// WHY: Verifies unsupported and incompatible persisted report drafts fail before deserialization.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers report schema-version and exact-field rejection. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.TooManyMethods",
  "PMD.AvoidDuplicateLiterals"
})
final class MavenElisionReportSchemaTest {
  /** Dropped-row collection key. */
  private static final String DROPPED_ROWS = "droppedArtifacts";

  /** Removed class count key on a whole-artifact row. */
  private static final String DROPPED_CLASSES = "programClassesRemoved";

  /** Removed class payload byte key on a whole-artifact row. */
  private static final String DROPPED_CLASS_BYTES = "uncompressedProgramClassBytesRemoved";

  /** Retained-JAR pruned class count key. */
  private static final String TRIMMED_CLASSES = "programClassesPruned";

  /** Retained-JAR pruned class payload byte key. */
  private static final String TRIMMED_CLASS_BYTES = "uncompressedProgramClassBytesPruned";

  /** JSON builder for adversarial report drafts. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Temporary report directory. */
  @TempDir Path temporaryDirectory;

  @Test
  void rejectsUnsupportedNonOneSnapshotWithRerunGuidance() throws IOException {
    final Path previous = temporaryDirectory.resolve("previous-report.json");
    java.nio.file.Files.writeString(previous, "{\"schemaVersion\":4}");

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported elision report schema version 4")
        .hasMessageContaining("run dependency-elider:elide");
  }

  @Test
  void rejectsSchemaOneDraftWithIncompatibleTopLevelFields() throws IOException {
    final Path previous = temporaryDirectory.resolve("incompatible-report-draft.json");
    java.nio.file.Files.writeString(previous, "{\"schemaVersion\":1,\"projectGroupId\":\"draft\"}");

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report fields do not match schema version 1")
        .hasMessageContaining("run dependency-elider:elide");
  }

  @Test
  void rejectsDroppedArtifactMissingClassMetrics() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.remove(DROPPED_CLASSES);
    row.remove(DROPPED_CLASS_BYTES);
    final Path previous = temporaryDirectory.resolve("missing-class-metrics.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report artifact row fields do not match schema version 1")
        .hasMessageContaining("run dependency-elider:elide");
  }

  @Test
  void rejectsNullDroppedArtifactClassMetrics() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.putNull(DROPPED_CLASSES);
    row.putNull(DROPPED_CLASS_BYTES);
    final Path previous = temporaryDirectory.resolve("null-dropped-metrics.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report artifact metric must be a nonnegative integer");
  }

  @Test
  void rejectsStringDroppedArtifactClassCount() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.put(DROPPED_CLASSES, "0");
    row.put(DROPPED_CLASS_BYTES, 0);
    final Path previous = temporaryDirectory.resolve("wrong-type-dropped-metrics.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("nonnegative integer: programClassesRemoved");
  }

  @Test
  void rejectsOutOfRangeDroppedArtifactClassCount() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = (ObjectNode) payload.withArray(DROPPED_ROWS).get(0);
    row.put(DROPPED_CLASSES, 2_147_483_648L);
    final Path previous = temporaryDirectory.resolve("out-of-range-dropped-count.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("nonnegative integer: programClassesRemoved");
  }

  @Test
  void rejectsNullTrimmedArtifactClassCount() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode trimmed =
        payload
            .withArray("trimmedArtifacts")
            .addObject()
            .put("coordinate", "example:trimmed:jar:1.0")
            .put(TRIMMED_CLASSES, 1)
            .put(TRIMMED_CLASS_BYTES, 10);
    trimmed.putNull(TRIMMED_CLASSES);
    final Path previous = temporaryDirectory.resolve("null-trimmed-metric.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("nonnegative integer: programClassesPruned");
  }

  @Test
  void rejectsNonTextArtifactCoordinate() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("trimmedArtifacts")
        .addObject()
        .put("coordinate", 7)
        .put(TRIMMED_CLASSES, 1)
        .put(TRIMMED_CLASS_BYTES, 10);
    final Path previous = temporaryDirectory.resolve("non-text-coordinate.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact coordinate must be nonblank text");
  }

  @Test
  void rejectsNonArrayCveComponents() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.put("removedCveComponents", "not-an-array");
    final Path previous = temporaryDirectory.resolve("non-array-cve.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report CVE rows must be arrays");
  }

  @Test
  void rejectsMalformedCveId() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("removedCveComponents")
        .addObject()
        .put("cveId", "INVALID-CVE")
        .put("coordinate", "example:dep:jar:1.0");
    final Path previous = temporaryDirectory.resolve("malformed-cve-id.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("cveId must be a valid CVE identifier");
  }

  @Test
  void rejectsBlankCveCoordinate() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("provenAbsentCves")
        .addObject()
        .put("cveId", "CVE-2026-10001")
        .put("coordinate", "   ");
    final Path previous = temporaryDirectory.resolve("blank-cve-coordinate.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("coordinate must be nonblank text");
  }

  @Test
  void rejectsBlankConservativeCveReason() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("potentiallyConservativeCves")
        .addObject()
        .put("cveId", "CVE-2026-68494")
        .put("coordinate", "example:dep:jar:1.0")
        .put("reason", "   ")
        .put("pomOverrideSnippet", "<xml/>");
    final Path previous = temporaryDirectory.resolve("blank-reason.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("reason must be a non-blank string");
  }

  @Test
  void rejectsNonBooleanSavedLayoutAssumption() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.put("assumeConventionalJavaSourceLayout", "false");
    final Path previous = temporaryDirectory.resolve("invalid-layout-flag.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("layout assumption must be a JSON boolean");
  }

  @Test
  void rejectsMalformedSourceReviewRowAndNonBooleanRowFlag() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    final ObjectNode row = validSourceReviewRow(payload);
    row.put("conventionalLayoutAssumed", "true");
    final Path previous = temporaryDirectory.resolve("invalid-source-review-flag.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("source review assumption must be a JSON boolean");
  }

  @Test
  void rejectsMalformedSourceReviewMatchShape() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    validSourceReviewRow(payload).putObject("matches").put("unexpected", true);
    final Path previous = temporaryDirectory.resolve("invalid-source-review-match.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("source review matches must be an array");
  }

  @Test
  void rejectsDuplicateKeysAndTrailingReportDocuments() throws IOException {
    final Path duplicate = temporaryDirectory.resolve("duplicate-report-key.json");
    final Path duplicateSource = temporaryDirectory.resolve("duplicate-source-review-key.json");
    final Path trailing = temporaryDirectory.resolve("trailing-report-document.json");
    java.nio.file.Files.writeString(duplicate, "{\"schemaVersion\":1,\"schemaVersion\":1}");
    java.nio.file.Files.writeString(
        duplicateSource,
        "{\"sourceReviewFindings\":[{\"coordinate\":\"a\",\"coordinate\":\"b\"}]}");
    java.nio.file.Files.writeString(trailing, "{\"schemaVersion\":1} {}");

    assertAll(
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(duplicate))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Duplicate field 'schemaVersion'"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(duplicateSource))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Duplicate field 'coordinate'"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(trailing))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Trailing data in elision report"));
  }

  @Test
  void rejectsNonCanonicalSourceCoordinatesAndSnapshotAssumptionMismatch() throws IOException {
    final ObjectNode coordinatePayload = currentReportShapeWithDroppedRow();
    validSourceReviewRow(coordinatePayload).put("coordinate", "example:dep:jar:1.0");
    final Path coordinate = temporaryDirectory.resolve("noncanonical-source-coordinate.json");
    JSON.writeValue(coordinate.toFile(), coordinatePayload);

    final ObjectNode flagPayload = currentReportShapeWithDroppedRow();
    validSourceReviewRow(flagPayload).put("conventionalLayoutAssumed", true);
    final Path flag = temporaryDirectory.resolve("source-flag-mismatch.json");
    JSON.writeValue(flag.toFile(), flagPayload);

    assertAll(
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(coordinate))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("coordinate must include its scope"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(flag))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("assumption must match snapshot flag"));
  }

  @Test
  void rejectsContradictorySavedSourceMatchDetails() throws IOException {
    final ObjectNode tierPayload = sourceMatchPayload();
    sourceMatch(tierPayload).put("multiReleaseTier", 17);
    final ObjectNode classPayload = sourceMatchPayload();
    sourceMatch(classPayload).put("classEntry", "org.other.Outer");
    final ObjectNode physicalPathPayload = sourceMatchPayload();
    sourceMatch(physicalPathPayload).put("physicalJarEntry", "org.example/Outer.class");
    final ObjectNode sourcePayload = sourceMatchPayload();
    sourceMatch(sourcePayload).put("sourceFileAttribute", "Different.java");
    final ObjectNode claimPayload = sourceMatchPayload();
    ((ObjectNode) claimPayload.withArray("sourceReviewFindings").get(0))
        .withArray("programFiles")
        .removeAll()
        .add("src/main/java/org/example/Other.java");
    final Path tier = writeReport("source-tier-mismatch.json", tierPayload);
    final Path classEntry = writeReport("source-class-mismatch.json", classPayload);
    final Path physicalPath =
        writeReport("source-physical-path-mismatch.json", physicalPathPayload);
    final Path source = writeReport("source-attribute-mismatch.json", sourcePayload);
    final Path claim = writeReport("source-claim-mismatch.json", claimPayload);

    assertAll(
        "a valid baseline is accepted and each contradictory match is rejected for its defect",
        this::assertValidSourceReviewReport,
        () -> assertInvalidSourceMatch(tier, "physical entry conflicts with tier"),
        () -> assertInvalidSourceMatch(classEntry, "class conflicts with physical entry"),
        () -> assertInvalidSourceMatch(physicalPath, "class conflicts with physical entry"),
        () -> assertInvalidSourceMatch(source, "conflicts with its programFiles claim"),
        () -> assertInvalidSourceMatch(claim, "must reference a saved programFiles claim"));
  }

  private void assertValidSourceReviewReport() throws IOException {
    final Path validReport = writeReport("valid-source-match.json", sourceMatchPayload());
    final MavenElisionReportSnapshot validSnapshot = MavenElisionReportWriter.read(validReport);
    assertThat(validSnapshot.sourceReviewFindings()).hasSize(1);
  }

  private static ObjectNode validSourceReviewRow(final ObjectNode payload) {
    final ObjectNode row =
        payload
            .withArray("sourceReviewFindings")
            .addObject()
            .put("cveId", "CVE-2026-10001")
            .put("coordinate", "example:dep:jar:1.0 (compile)")
            .put("sourceRecordSha256", "a".repeat(64))
            .put("cnaAffectedEntryIdentity", "containers.cna.affected[0]")
            .put("affectedProductIdentity", "Example dep")
            .put("conventionalLayoutAssumed", false)
            .put("unresolvedRationale", "Verify source to class attribution");
    row.putArray("programFiles").add("src/main/java/org/example/Outer.java");
    row.putArray("programRoutines");
    row.putArray("matches")
        .addObject()
        .put("programFile", "src/main/java/org/example/Outer.java")
        .put("physicalJarEntry", "org/example/Outer.class")
        .put("multiReleaseTier", 0)
        .put("classEntry", "org.example.Outer")
        .put("sourceFileAttribute", "Outer.java")
        .put(
            "packagePathComparison",
            "source path package suffix matches class package org.example; exact source location "
                + "and sibling class set remain unverified (src/main/java/org/example/Outer.java)")
        .put("originalArchiveSha256", "b".repeat(64));
    return row;
  }

  private static ObjectNode sourceMatch(final ObjectNode payload) {
    return (ObjectNode)
        payload.withArray("sourceReviewFindings").get(0).withArray("matches").get(0);
  }

  private Path writeReport(final String name, final ObjectNode payload) throws IOException {
    final Path report = temporaryDirectory.resolve(name);
    JSON.writeValue(report.toFile(), payload);
    return report;
  }

  private static void assertInvalidSourceMatch(final Path report, final String diagnostic) {
    assertThatThrownBy(() -> MavenElisionReportWriter.read(report))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(diagnostic);
  }

  private static ObjectNode sourceMatchPayload() {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.put("wholeArtifactsDropped", 0);
    payload.put("originalJarBytesDropped", 0);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    payload.withArray(DROPPED_ROWS).removeAll();
    validSourceReviewRow(payload);
    return payload;
  }

  static ObjectNode currentReportShapeWithDroppedRow() {
    final ObjectNode payload = JSON.createObjectNode();
    payload.put("schemaVersion", 1);
    payload.put("projectGroupId", "example");
    payload.put("projectArtifactId", "consumer");
    payload.put("projectVersion", "1.0");
    payload.put("projectBaseDirectory", "/tmp/consumer");
    payload.put("generatedAt", "2026-10-28T00:00:00Z");
    payload.put("wholeArtifactsDropped", 1);
    payload.put("originalJarBytesDropped", 1);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    payload
        .putArray(DROPPED_ROWS)
        .addObject()
        .put("coordinate", "example:old:jar:1.0 (compile)")
        .put("originalJarBytes", 1)
        .put(DROPPED_CLASSES, 0)
        .put(DROPPED_CLASS_BYTES, 0);
    payload.putArray("rawDroppedCoordinates");
    payload.put("programClassesPruned", 0);
    payload.put("uncompressedProgramClassBytesPruned", 0);
    payload.putArray("trimmedArtifacts");
    payload.putArray("removedCveComponents");
    payload.putArray("provenAbsentCves");
    payload.putArray("inactivePreconditionCves");
    payload.putArray("potentiallyConservativeCves");
    payload.put("assumeConventionalJavaSourceLayout", false);
    payload.putArray("sourceReviewFindings");
    final ObjectNode graph = payload.putObject("mediatedGraph");
    graph.put("available", false);
    graph.put("unavailableReason", "No graph was provided");
    graph.putNull("captureToken");
    graph.putNull("projectKey");
    graph.putNull("beforeFingerprint");
    graph.putNull("snapshot");
    graph.putArray("nodeStatuses");
    graph.putArray("artifactPaths");
    return payload;
  }
}
