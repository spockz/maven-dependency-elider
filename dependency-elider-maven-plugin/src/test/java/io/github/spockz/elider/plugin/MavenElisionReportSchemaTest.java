// WHY: Verifies unsupported and incompatible persisted report drafts fail before deserialization.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
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
  void rejectsSchemaOneSnapshotMissingVerifiedStructuredProofCollection() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.remove("verifiedStructuredProofs");
    final Path previous =
        temporaryDirectory.resolve("missing-verified-structured-proof-array.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report fields do not match schema version 1");
  }

  @Test
  void rejectsSchemaOneSnapshotWithNullVerifiedStructuredProofCollection() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.putNull("verifiedStructuredProofs");
    final Path previous = temporaryDirectory.resolve("null-verified-structured-proof-array.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Elision report verifiedStructuredProofs must be an array");
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
  void rejectsMissingOrMalformedPolicyIdentity() throws IOException {
    final ObjectNode missingPolicy = currentReportShapeWithDroppedRow();
    missingPolicy.remove("policy");
    final Path missing = temporaryDirectory.resolve("missing-policy.json");
    JSON.writeValue(missing.toFile(), missingPolicy);

    final ObjectNode malformedPolicy = currentReportShapeWithDroppedRow();
    malformedPolicy.with("policy").put("operationFingerprint", "not-a-digest");
    final Path malformed = temporaryDirectory.resolve("malformed-policy.json");
    JSON.writeValue(malformed.toFile(), malformedPolicy);

    final ObjectNode noncanonicalPolicy = currentReportShapeWithDroppedRow();
    noncanonicalPolicy
        .with("policy")
        .putArray("retainedArtifacts")
        .add("org.example:kept::jar:")
        .add("org.example:kept::jar:");
    final Path noncanonical = temporaryDirectory.resolve("noncanonical-policy.json");
    JSON.writeValue(noncanonical.toFile(), noncanonicalPolicy);

    final ObjectNode invalidCoordinatePolicy = currentReportShapeWithDroppedRow();
    invalidCoordinatePolicy.with("policy").putArray("banishedDependencies").add("org.example:*");
    final Path invalidCoordinate = temporaryDirectory.resolve("invalid-policy-coordinate.json");
    JSON.writeValue(invalidCoordinate.toFile(), invalidCoordinatePolicy);

    assertAll(
        "schema-one policy identity is required and structurally valid",
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(missing))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Elision report fields do not match schema version 1"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(malformed))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Elision report policy values are malformed"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(noncanonical))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Elision report policy coordinates are not canonical"),
        () ->
            assertThatThrownBy(() -> MavenElisionReportWriter.read(invalidCoordinate))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Elision report policy coordinates are invalid"));
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
  void validatesAppliedBanCoordinatesAndPolicyCorrespondence() throws IOException {
    final ObjectNode valid = appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    final Path validPath = temporaryDirectory.resolve("valid-applied-ban.json");
    JSON.writeValue(validPath.toFile(), valid);

    final ObjectNode wrongFamily =
        appliedBanReport("example:drop", "example:other:jar:1.0 (runtime)");
    final Path wrongFamilyPath = temporaryDirectory.resolve("wrong-ban-family.json");
    JSON.writeValue(wrongFamilyPath.toFile(), wrongFamily);

    final ObjectNode unsupportedType =
        appliedBanReport("example:drop", "example:drop:zip:1.0 (runtime)");
    final Path unsupportedTypePath = temporaryDirectory.resolve("unsupported-ban-type.json");
    JSON.writeValue(unsupportedTypePath.toFile(), unsupportedType);

    final ObjectNode unsupportedScope =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (test)");
    final Path unsupportedScopePath = temporaryDirectory.resolve("unsupported-ban-scope.json");
    JSON.writeValue(unsupportedScopePath.toFile(), unsupportedScope);

    final ObjectNode policyMismatch =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    policyMismatch.with("policy").putArray("banishedDependencies").add("example:other");
    final Path policyMismatchPath = temporaryDirectory.resolve("applied-ban-policy-mismatch.json");
    JSON.writeValue(policyMismatchPath.toFile(), policyMismatch);

    assertAll(
        "applied ban outcomes correspond exactly to normalized policy and supported GAVCE values",
        () -> MavenElisionReportPayloadValidator.validate(valid),
        () -> assertThat(valid.path("appliedBans")).hasSize(1),
        () -> assertInvalidAppliedBan(wrongFamilyPath, "G:A does not match its dependency"),
        () -> assertInvalidAppliedBan(unsupportedTypePath, "must be a compile/runtime JAR"),
        () -> assertInvalidAppliedBan(unsupportedScopePath, "must be a compile/runtime JAR"),
        () -> assertInvalidAppliedBan(policyMismatchPath, "do not match policy"));
  }

  @Test
  void rejectsAppliedBanThatDoesNotMatchWholeArtifactOutputDisposition() throws IOException {
    final ObjectNode missingDrop =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    missingDrop.withArray(DROPPED_ROWS).removeAll();
    final Path missingDropPath = temporaryDirectory.resolve("ban-without-drop.json");
    JSON.writeValue(missingDropPath.toFile(), missingDrop);

    final ObjectNode missingGraph =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    setGraph(missingGraph, MediatedGraphReport.unavailable("No graph was provided"));
    final Path missingGraphPath = temporaryDirectory.resolve("ban-without-graph.json");
    JSON.writeValue(missingGraphPath.toFile(), missingGraph);

    final ObjectNode retained = appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    setGraph(
        retained,
        MediatedGraphBanReportTestSupport.droppedAndRetained(
            banArtifact("1.0", ""), banArtifact("1.0", ""), "example:consumer:1.0"));
    final Path retainedPath = temporaryDirectory.resolve("ban-also-retained.json");
    JSON.writeValue(retainedPath.toFile(), retained);

    final ObjectNode retainedPolicyOtherVersion =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    retainedPolicyOtherVersion
        .with("policy")
        .putArray("retainedArtifacts")
        .add("example:drop:2.0:jar:tests");
    final Path retainedPolicyPath =
        temporaryDirectory.resolve("ban-conflicts-with-retention-policy.json");
    JSON.writeValue(retainedPolicyPath.toFile(), retainedPolicyOtherVersion);

    final ObjectNode trimmed = appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    trimmed
        .withArray("trimmedArtifacts")
        .addObject()
        .put("coordinate", "example:drop:jar:1.0 (runtime)")
        .put(TRIMMED_CLASSES, 0)
        .put(TRIMMED_CLASS_BYTES, 0);
    final Path trimmedPath = temporaryDirectory.resolve("ban-also-trimmed.json");
    JSON.writeValue(trimmedPath.toFile(), trimmed);

    assertAll(
        "forced absence agrees with every persisted artifact disposition",
        () -> assertInvalidAppliedBan(missingDropPath, "missing from droppedArtifacts"),
        () -> assertInvalidAppliedBan(missingGraphPath, "require an available mediated graph"),
        () ->
            assertInvalidAppliedBan(retainedPolicyPath, "conflicts with retained-artifact policy"),
        () -> assertInvalidAppliedBan(retainedPath, "also appears in retained or trimmed"),
        () -> assertInvalidAppliedBan(trimmedPath, "also appears in retained or trimmed"));
  }

  @Test
  void rejectsBanIdentityFamilyPresentInAnyPersistedOutputDisposition() throws IOException {
    final ObjectNode excludedWithOriginalAuditOnly = excludedBanReport("example:drop");
    final Path validExcludedPath =
        writeReport("valid-excluded-ban-original-audit.json", excludedWithOriginalAuditOnly);

    final ObjectNode forcedRetainedOtherVersion =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    setGraph(
        forcedRetainedOtherVersion,
        MediatedGraphBanReportTestSupport.droppedAndRetained(
            banArtifact("1.0", ""), banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path forcedRetainedPath =
        writeReport("forced-ban-retained-other-version.json", forcedRetainedOtherVersion);

    final ObjectNode forcedTrimmedOtherVersion =
        appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    addTrimmedArtifact(forcedTrimmedOtherVersion, "example:drop:jar:2.0:tests (runtime)");
    setGraph(
        forcedTrimmedOtherVersion,
        MediatedGraphBanReportTestSupport.droppedAndTrimmed(
            banArtifact("1.0", ""), banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path forcedTrimmedPath =
        writeReport("forced-ban-trimmed-other-version.json", forcedTrimmedOtherVersion);

    final ObjectNode excludedRetained = excludedBanReport("example:drop");
    setGraph(
        excludedRetained,
        MediatedGraphBanReportTestSupport.retained(
            banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path excludedRetainedPath =
        writeReport("excluded-ban-retained-output.json", excludedRetained);

    final ObjectNode excludedTrimmed = excludedBanReport("example:drop");
    addTrimmedArtifact(excludedTrimmed, "example:drop:jar:2.0:tests (runtime)");
    setGraph(
        excludedTrimmed,
        MediatedGraphBanReportTestSupport.trimmed(
            banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path excludedTrimmedPath =
        writeReport("excluded-ban-trimmed-output.json", excludedTrimmed);

    assertAll(
        "ban status is consistent with the complete G:A output disposition",
        () -> MavenElisionReportWriter.read(validExcludedPath),
        () -> assertInvalidAppliedBan(forcedRetainedPath, "also appears in retained or trimmed"),
        () -> assertInvalidAppliedBan(forcedTrimmedPath, "also appears in retained or trimmed"),
        () ->
            assertInvalidAppliedBan(
                excludedRetainedPath,
                "Excluded-before-resolution ban appears in retained or trimmed"),
        () ->
            assertInvalidAppliedBan(
                excludedTrimmedPath,
                "Excluded-before-resolution ban appears in retained or trimmed"));
  }

  @Test
  void unmatchedBanMustBeAbsentFromEveryPersistedInventorySection() throws IOException {
    final ObjectNode valid = excludedBanReport("example:drop");
    markBanUnmatched(valid);
    final Path validPath = writeReport("valid-unmatched-ban.json", valid);
    final ObjectNode unavailableGraph = valid.deepCopy();
    setGraph(unavailableGraph, MediatedGraphReport.unavailable("No graph was provided"));
    final Path unavailableGraphPath =
        writeReport("valid-unmatched-ban-without-graph.json", unavailableGraph);
    final ObjectNode unrelated = valid.deepCopy();
    setGraph(
        unrelated,
        MediatedGraphBanReportTestSupport.retained(
            ArtifactCoordinate.of("example", "other", "1.0"), "example:consumer:1.0"));
    final Path unrelatedPath = writeReport("valid-unmatched-ban-unrelated-graph.json", unrelated);

    final ObjectNode retained = valid.deepCopy();
    setGraph(
        retained,
        MediatedGraphBanReportTestSupport.retained(
            banArtifact("2.0", "tests"), "example:consumer:1.0"));
    final Path retainedPath = writeReport("unmatched-ban-retained.json", retained);

    final ObjectNode dropped = appliedBanReport("example:drop", "example:drop:jar:1.0 (runtime)");
    markBanUnmatched(dropped);
    final Path droppedPath = writeReport("unmatched-ban-dropped.json", dropped);
    setGraph(dropped, MediatedGraphReport.unavailable("No graph was provided"));
    final Path droppedWithoutGraphPath =
        writeReport("unmatched-ban-dropped-without-graph.json", dropped);

    final ObjectNode trimmed = unavailableGraph.deepCopy();
    addTrimmedArtifact(trimmed, "example:drop:jar:2.0:tests (runtime)");
    final Path trimmedPath = writeReport("unmatched-ban-trimmed-without-graph.json", trimmed);

    final ObjectNode graphOnly = valid.deepCopy();
    setGraph(
        graphOnly,
        MediatedGraphBanReportTestSupport.dropped(banArtifact("1.0", ""), "example:consumer:1.0"));
    final Path graphOnlyPath = writeReport("unmatched-ban-elided-graph-node.json", graphOnly);

    assertAll(
        "unmatched requests cannot conceal any resolved G:A match, regardless of disposition",
        () -> MavenElisionReportWriter.read(validPath),
        () -> MavenElisionReportWriter.read(unavailableGraphPath),
        () -> MavenElisionReportWriter.read(unrelatedPath),
        () -> assertInvalidAppliedBan(retainedPath, "Unmatched ban appears"),
        () -> assertInvalidAppliedBan(droppedPath, "Unmatched ban appears"),
        () -> assertInvalidAppliedBan(droppedWithoutGraphPath, "Unmatched ban appears"),
        () -> assertInvalidAppliedBan(trimmedPath, "Unmatched ban appears"),
        () -> assertInvalidAppliedBan(graphOnlyPath, "Unmatched ban appears"));
  }

  private static void markBanUnmatched(final ObjectNode payload) {
    final ObjectNode ban = (ObjectNode) payload.withArray("appliedBans").get(0);
    ban.put("status", "UNMATCHED");
    ban.put("applied", false);
    ban.withArray("matchedArtifacts").removeAll();
    ban.withArray("originalArtifacts").removeAll();
  }

  private ObjectNode excludedBanReport(final String dependency) throws IOException {
    final ObjectNode payload = appliedBanReport(dependency, dependency + ":jar:1.0 (runtime)");
    payload.withArray(DROPPED_ROWS).removeAll();
    payload.put("wholeArtifactsDropped", 0);
    payload.put("originalJarBytesDropped", 0);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    final ObjectNode ban = (ObjectNode) payload.withArray("appliedBans").get(0);
    ban.put("status", "EXCLUDED_BEFORE_RESOLUTION");
    ban.withArray("matchedArtifacts").removeAll();
    setGraph(payload, MediatedGraphBanReportTestSupport.empty("example:consumer:1.0"));
    return payload;
  }

  private static void addTrimmedArtifact(final ObjectNode payload, final String coordinate) {
    payload
        .withArray("trimmedArtifacts")
        .addObject()
        .put("coordinate", coordinate)
        .put(TRIMMED_CLASSES, 0)
        .put(TRIMMED_CLASS_BYTES, 0);
  }

  private ObjectNode appliedBanReport(final String dependency, final String coordinate)
      throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.put("wholeArtifactsDropped", 1);
    payload.put("originalJarBytesDropped", 0);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    payload
        .putArray(DROPPED_ROWS)
        .removeAll()
        .addObject()
        .put("coordinate", coordinate)
        .put("originalJarBytes", 0)
        .put(DROPPED_CLASSES, 0)
        .put(DROPPED_CLASS_BYTES, 0);
    payload.with("policy").putArray("banishedDependencies").add(dependency);
    final ObjectNode ban = payload.putArray("appliedBans").addObject();
    ban.put("dependency", dependency);
    ban.put("status", "FORCED_ABSENT_AFTER_RESOLUTION");
    ban.putArray("matchedArtifacts").add(coordinate);
    ban.putArray("originalArtifacts").add(coordinate);
    ban.put("applied", true);
    setGraph(
        payload,
        MediatedGraphBanReportTestSupport.dropped(banArtifact("1.0", ""), "example:consumer:1.0"));
    return payload;
  }

  private static void setGraph(final ObjectNode payload, final MediatedGraphReport graph) {
    payload.set("mediatedGraph", JSON.valueToTree(graph));
  }

  private static ArtifactCoordinate banArtifact(final String version, final String classifier) {
    return new ArtifactCoordinate("example", "drop", version, "jar", classifier, "runtime");
  }

  private void assertInvalidAppliedBan(final Path path, final String message) {
    assertThatThrownBy(() -> MavenElisionReportWriter.read(path))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(message);
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
  void rejectsInactiveCveRowsWithoutMissingPrerequisiteDetails() throws IOException {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload
        .withArray("inactivePreconditionCves")
        .addObject()
        .put("cveId", "CVE-2026-10001")
        .put("coordinate", "example:affected:jar:1.0")
        .putArray("missingPrerequisites");
    final Path previous = temporaryDirectory.resolve("missing-inactive-cause.json");
    JSON.writeValue(previous.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(previous))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("must include missing prerequisite details");
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
  void validatesPackageAndHeuristicAdvisoryRowsStrictly() {
    assertAll(
        "report-only advisory rows retain source identity and exact component scope",
        () -> {
          final ObjectNode payload = advisoryReportPayload();
          final Path valid = temporaryDirectory.resolve("valid-advisory-report.json");
          JSON.writeValue(valid.toFile(), payload);
          assertThat(MavenElisionReportWriter.read(valid).advisoryReview().packageAdvisories())
              .hasSize(1);
        },
        () ->
            assertInvalidAdvisoryReport(
                "unsupported-package-applicability.json",
                payload ->
                    ((ObjectNode) payload.get("advisoryReview").get("packageAdvisories").get(0))
                        .put("applicability", "HIGH"),
                "package applicability is unsupported"),
        () ->
            assertInvalidAdvisoryReport(
                "mismatched-package-coordinate.json",
                payload ->
                    ((ObjectNode) payload.get("advisoryReview").get("packageAdvisories").get(0))
                        .put("packageName", "other:artifact"),
                "package advisory identity conflicts with coordinate"),
        () ->
            assertInvalidAdvisoryReport(
                "package-applicability-conflicts-with-claims.json",
                payload ->
                    ((ObjectNode) payload.get("advisoryReview").get("packageAdvisories").get(0))
                        .put("applicability", "NOT_APPLICABLE"),
                "package applicability conflicts with raw OSV claims"),
        () ->
            assertInvalidAdvisoryReport(
                "heuristic-cve-not-owned.json",
                payload ->
                    ((ObjectNode) payload.get("advisoryReview").get("heuristicAdvisories").get(0))
                        .put("cveId", "CVE-2026-99999"),
                "Heuristic CVE must identify its OSV record or alias"),
        () ->
            assertInvalidAdvisoryReport(
                "heuristic-source-owner-not-owned.json",
                payload ->
                    ((ObjectNode) payload.get("advisoryReview").get("heuristicAdvisories").get(0))
                        .put("sourceRecordId", "GHSA-other#details"),
                "Heuristic source record must identify its OSV owner"),
        () ->
            assertInvalidAdvisoryReport(
                "heuristic-package-identity-mismatch-unresolved.json",
                payload -> {
                  final ObjectNode row =
                      (ObjectNode) payload.get("advisoryReview").get("heuristicAdvisories").get(0);
                  row.put("packageName", "other:artifact");
                  row.put("applicability", "UNRESOLVED");
                },
                "package advisory identity conflicts with coordinate"),
        () ->
            assertInvalidAdvisoryReport(
                "heuristic-applicability-disagrees-with-package-owner.json",
                payload ->
                    ((ObjectNode) payload.get("advisoryReview").get("heuristicAdvisories").get(0))
                        .put("applicability", "UNRESOLVED"),
                "Heuristic applicability conflicts with its unique OSV package owner"),
        () ->
            assertInvalidAdvisoryReport(
                "heuristic-nested-class.json",
                payload ->
                    ((ObjectNode) payload.get("advisoryReview").get("heuristicAdvisories").get(0))
                        .withArray("candidateClasses")
                        .set(0, JSON.getNodeFactory().textNode("example.old.Candidate$Nested")),
                "candidateClasses must contain top-level class names"),
        () ->
            assertInvalidAdvisoryReport(
                "heuristic-versioned-dependency.json",
                payload ->
                    ((ObjectNode) payload.get("advisoryReview").get("heuristicAdvisories").get(0))
                        .withArray("candidateDependencies")
                        .add("example:library:1.0"),
                "candidateDependencies must be exact group:artifact values"),
        () ->
            assertInvalidAdvisoryReport(
                "proof-confidence-in-heuristic.json",
                payload ->
                    ((ObjectNode) payload.get("advisoryReview").get("heuristicAdvisories").get(0))
                        .put("confidence", "HIGH"),
                "heuristic confidence is unsupported"));
  }

  private void assertInvalidAdvisoryReport(
      final String fileName,
      final java.util.function.Consumer<ObjectNode> mutation,
      final String diagnostic)
      throws IOException {
    final ObjectNode payload = advisoryReportPayload();
    mutation.accept(payload);
    final Path invalid = temporaryDirectory.resolve(fileName);
    JSON.writeValue(invalid.toFile(), payload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(invalid))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(diagnostic);
  }

  private static ObjectNode advisoryReportPayload() {
    final ObjectNode payload = currentReportShapeWithDroppedRow();
    payload.put("wholeArtifactsDropped", 0);
    payload.put("originalJarBytesDropped", 0);
    payload.put("droppedProgramClassEntries", 0);
    payload.put("droppedProgramClassBytes", 0);
    payload.withArray(DROPPED_ROWS).removeAll();
    payload.withArray("rawDroppedCoordinates").removeAll();
    final ObjectNode review = (ObjectNode) payload.get("advisoryReview");
    review
        .putArray("packageAdvisories")
        .addObject()
        .put("osvId", "GHSA-heuristic")
        .putArray("aliases")
        .add("CVE-2026-12345");
    final ObjectNode packageRow = (ObjectNode) review.withArray("packageAdvisories").get(0);
    packageRow.put("coordinate", "example:old:jar:1.0 (compile)");
    packageRow.put("ecosystem", "Maven");
    packageRow.put("packageName", "example:old");
    packageRow.putArray("affectedVersions").add("1.0");
    packageRow.putArray("ranges");
    packageRow.put("applicability", "APPLICABLE");
    packageRow.put("applicabilityRationale", "Exact version listed");
    packageRow.put("inventoryDisposition", "REMOVED");
    packageRow.putNull("sourceRecordSha256");

    review
        .putArray("heuristicAdvisories")
        .addObject()
        .put("osvId", "GHSA-heuristic")
        .putArray("aliases")
        .add("CVE-2026-12345");
    final ObjectNode heuristic = (ObjectNode) review.withArray("heuristicAdvisories").get(0);
    heuristic.put("cveId", "CVE-2026-12345");
    heuristic.put("coordinate", "example:old:jar:1.0 (compile)");
    heuristic.put("ecosystem", "Maven");
    heuristic.put("packageName", "example:old");
    heuristic.put("versionRangeSpec", "[1.0,2.0)");
    heuristic.put("applicability", "APPLICABLE");
    heuristic.put("applicabilityRationale", "Exact version listed");
    heuristic.put("inventoryDisposition", "REMOVED");
    heuristic.put("origin", "DESCRIPTION");
    heuristic.put("sourceRecordId", "GHSA-heuristic#details");
    heuristic.putNull("sourceUrl");
    heuristic.putNull("sourceRecordSha256");
    heuristic.put("confidence", "MEDIUM");
    heuristic.putArray("candidateClasses").add("example.old.Candidate");
    heuristic.putArray("candidateDependencies");
    return payload;
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
            .put("osvId", "GHSA-example")
            .put("cveId", "CVE-2026-10001")
            .put("coordinate", "example:dep:jar:1.0 (compile)")
            .put("sourceRecordSha256", "a".repeat(64))
            .put("cnaAffectedEntryIdentity", "containers.cna.affected[0]")
            .put("affectedProductIdentity", "Example dep")
            .put("conventionalLayoutAssumed", false)
            .put("applicability", "UNRESOLVED")
            .put("applicabilityRationale", "Raw version claims do not establish applicability")
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
    payload.putArray("verifiedStructuredProofs");
    final ObjectNode policy = payload.putObject("policy");
    policy.putArray("retainedArtifacts");
    policy.putArray("banishedDependencies");
    policy.put("operationFingerprint", MavenElisionGraphBinding.sha256(java.util.List.of()));
    payload.putObject("advisoryReview").putArray("packageAdvisories");
    ((ObjectNode) payload.get("advisoryReview")).putArray("heuristicAdvisories");
    payload.set(
        "exclusionReview",
        JSON.valueToTree(
            ExclusionReview.unavailable("No pre-injection declaration capture is available")));
    payload.putArray("appliedBans");
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
